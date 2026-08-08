--------------------------- MODULE guardian ---------------------------
EXTENDS Naturals, Sequences, FiniteSets

(***************************************************************************
This bounded specification mirrors the executable state model in
formal/check_model.py. It represents the reference-monitor boundary rather
than the entire Python implementation. The model includes capability scope,
one-level delegation, parent revocation, capability/permit expiry, policy and
safety predicates, state-bound permits, single-use execution, and evidence.
***************************************************************************)

Requests == {"observe", "restricted", "unsafe"}
Capabilities == {"parent", "child", "escalated_child"}
Delegatable == {"child", "escalated_child"}
MaxTime == 3
MaxStateVersion == 1
MaxPermits == 2
PermitTTL == 2

Min2(a, b) == IF a <= b THEN a ELSE b

RequiredAuthority(r) ==
    CASE r = "observe" -> 1
      [] r = "restricted" -> 2
      [] OTHER -> 1

PolicyAllowed(r) == r # "restricted"
InvariantSafe(r) == r # "unsafe"

CapabilityAuthority(c) ==
    CASE c = "escalated_child" -> 2
      [] OTHER -> 1

CapabilityExpiry(c) == 3

Parent(c) ==
    CASE c = "child" -> "parent"
      [] c = "escalated_child" -> "parent"
      [] OTHER -> ""

VARIABLES now, stateVersion, delegated, revoked, permits, usedPermits,
          executed, evidence, nextPermitId

vars == <<now, stateVersion, delegated, revoked, permits, usedPermits,
          executed, evidence, nextPermitId>>

Available(c) == Parent(c) = "" \/ c \in delegated

ParentActive(c) ==
    Parent(c) = "" \/
      /\ Parent(c) \notin revoked
      /\ now < CapabilityExpiry(Parent(c))

LineageActive(c) ==
    /\ Available(c)
    /\ c \notin revoked
    /\ now < CapabilityExpiry(c)
    /\ ParentActive(c)

DelegationSubset(c) ==
    /\ c \in Delegatable
    /\ Parent(c) # ""
    /\ CapabilityAuthority(c) <= CapabilityAuthority(Parent(c))
    /\ CapabilityExpiry(c) <= CapabilityExpiry(Parent(c))

CapAuthorizes(r, c) ==
    /\ LineageActive(c)
    /\ RequiredAuthority(r) <= CapabilityAuthority(c)

Init ==
    /\ now = 0
    /\ stateVersion = 0
    /\ delegated = {}
    /\ revoked = {}
    /\ permits = {}
    /\ usedPermits = {}
    /\ executed = <<>>
    /\ evidence = <<>>
    /\ nextPermitId = 1

Delegate(c) ==
    /\ c \in Delegatable
    /\ c \notin delegated
    /\ LineageActive(Parent(c))
    /\ DelegationSubset(c)
    /\ delegated' = delegated \cup {c}
    /\ UNCHANGED <<now, stateVersion, revoked, permits, usedPermits,
                    executed, evidence, nextPermitId>>

Authorize(r, c) ==
    /\ r \in Requests
    /\ c \in Capabilities
    /\ nextPermitId <= MaxPermits
    /\ CapAuthorizes(r, c)
    /\ PolicyAllowed(r)
    /\ InvariantSafe(r)
    /\ LET p == [id |-> nextPermitId,
                  request |-> r,
                  capability |-> c,
                  issuedAt |-> now,
                  expiresAt |-> Min2(now + PermitTTL, CapabilityExpiry(c)),
                  boundState |-> stateVersion]
       IN permits' = permits \cup {p}
    /\ nextPermitId' = nextPermitId + 1
    /\ UNCHANGED <<now, stateVersion, delegated, revoked, usedPermits,
                    executed, evidence>>

Revoke(c) ==
    /\ c \in Capabilities
    /\ Available(c)
    /\ c \notin revoked
    /\ revoked' = revoked \cup {c}
    /\ UNCHANGED <<now, stateVersion, delegated, permits, usedPermits,
                    executed, evidence, nextPermitId>>

Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ UNCHANGED <<stateVersion, delegated, revoked, permits, usedPermits,
                    executed, evidence, nextPermitId>>

StateChange ==
    /\ stateVersion < MaxStateVersion
    /\ stateVersion' = stateVersion + 1
    /\ UNCHANGED <<now, delegated, revoked, permits, usedPermits,
                    executed, evidence, nextPermitId>>

PermitExecutable(p) ==
    /\ p \in permits
    /\ p.id \notin usedPermits
    /\ now < p.expiresAt
    /\ LineageActive(p.capability)
    /\ stateVersion = p.boundState
    /\ RequiredAuthority(p.request) <= CapabilityAuthority(p.capability)
    /\ PolicyAllowed(p.request)
    /\ InvariantSafe(p.request)

Execute(p) ==
    /\ PermitExecutable(p)
    /\ usedPermits' = usedPermits \cup {p.id}
    /\ executed' = Append(executed,
            [permitId |-> p.id,
             authorized |-> RequiredAuthority(p.request) <= CapabilityAuthority(p.capability),
             policyAllowed |-> PolicyAllowed(p.request),
             invariantSafe |-> InvariantSafe(p.request),
             lineageActive |-> LineageActive(p.capability),
             stateBound |-> stateVersion = p.boundState,
             unexpired |-> now < p.expiresAt])
    /\ evidence' = Append(evidence, p.id)
    /\ UNCHANGED <<now, stateVersion, delegated, revoked, permits, nextPermitId>>

Next ==
    \/ \E c \in Delegatable : Delegate(c)
    \/ \E r \in Requests, c \in Capabilities : Authorize(r, c)
    \/ \E c \in Capabilities : Revoke(c)
    \/ Tick
    \/ StateChange
    \/ \E p \in permits : Execute(p)

NoExecutionWithoutAuthorization ==
    \A i \in 1..Len(executed) : executed[i].authorized

NoPolicyDeniedExecution ==
    \A i \in 1..Len(executed) : executed[i].policyAllowed

NoUnsafeExecution ==
    \A i \in 1..Len(executed) : executed[i].invariantSafe

NoRevokedOrExpiredExecution ==
    \A i \in 1..Len(executed) :
        executed[i].lineageActive /\ executed[i].unexpired

StateBoundExecution ==
    \A i \in 1..Len(executed) : executed[i].stateBound

EvidenceForExecution == evidence = [i \in 1..Len(executed) |-> executed[i].permitId]

PermitSingleUse ==
    Cardinality({executed[i].permitId : i \in 1..Len(executed)}) = Len(executed)

DelegationCannotIncreaseAuthority ==
    \A c \in delegated : DelegationSubset(c)

Spec == Init /\ [][Next]_vars

=============================================================================
