--------------------------- MODULE Multipart ---------------------------
(***************************************************************************)
(* A model of blindbucket's manifest coordination, as described in         *)
(* CONCEPT.md sections 10.6, 10.8 and 11.2.                                *)
(*                                                                         *)
(* The model covers coordination only, never cryptography.  Data keys,     *)
(* segments, chunk authentication and part contents are all absent: what   *)
(* is at stake here is the ORDER of upstream calls made by requests that   *)
(* run concurrently, possibly on different proxy instances, against the    *)
(* same object key.                                                        *)
(*                                                                         *)
(* Everything happens on one key.  That is not a simplification of the     *)
(* problem, it is the problem: manifests are per key, gc works per key     *)
(* (R4), and two uploads to different keys never interact.                 *)
(*                                                                         *)
(* Invariants under check:                                                 *)
(*                                                                         *)
(*   I1  Every visible multipart object has a manifest with its manifest   *)
(*       id.  An object that fails I1 is still recoverable from its data   *)
(*       key, but every GET against it fails.                              *)
(*                                                                         *)
(*   I2  Rotation never replaces a newer version of an object with an      *)
(*       older one (no lost update).                                       *)
(*                                                                         *)
(* Four CONSTANTS select which set of rules is modelled, so that the same  *)
(* spec can be run both as the design under test and as the flawed version *)
(* 0.1 design that has to produce a counterexample.  See README.md next to *)
(* this file for the configurations and what each is expected to report.   *)
(***************************************************************************)
EXTENDS FiniteSets, TLC

CONSTANTS
    Uploads,      \* The concurrent multipart uploads, e.g. {u1, u2, u3}.

    CleanupMode,  \* Step 5 of the completion order in 10.6.
                  \*   "r3"  - delete only the manifest id observed at step 2
                  \*   "v01" - delete "all other manifests of this key"

    GcMode,       \* The order of the gc pass in R4.
                  \*   "r4"      - list, check open uploads, head, delete
                  \*   "v01"     - list, head, delete (no open-upload check)
                  \*   "swapped" - check open uploads, list, head, delete

    RotateMode    \* The final write of `blindbucket rotate` (11.2).
                  \*   "conditional"   - If-Match on the etag read at the start
                  \*   "unconditional" - the --allow-unconditional escape hatch
                  \*   "off"           - no rotation runs at all.  The I1
                  \*                     counterexamples use this, so that the
                  \*                     traces contain only operations that
                  \*                     M4 implements and can replay as
                  \*                     integration tests.

\* Manifest ids.  Every operation that makes an object visible mints a fresh
\* one (R1), and in this model each process makes an object visible at most
\* once -- so a process may simply use its own name as its manifest id, and
\* the set of ids is finite without weakening the model.
RotId  == "rot"
PutId  == "put"
DelId  == "del"
InitId == "m0"      \* the manifest of the object the model starts from
NoMid  == "nil"     \* "this object has no manifest id" (absent or single-part)

Mids    == Uploads \cup {RotId, InitId}
Writers == Uploads \cup {RotId, PutId, DelId, "init"}
Kinds   == {"absent", "single", "multi"}

ASSUME CleanupMode \in {"r3", "v01"}
ASSUME GcMode      \in {"r4", "v01", "swapped"}
ASSUME RotateMode  \in {"conditional", "unconditional", "off"}

\* Symmetry: the uploads are interchangeable, so TLC may quotient the state
\* space by permutations of them.  Sound here because neither the algorithm
\* nor I1/I2 distinguishes one upload from another.
Perms == Permutations(Uploads)

(*--algorithm multipart {

variables
    \* The object version visible at the upstream for the key.  `by` stands in
    \* for the etag: each writer writes at most once, so "by is unchanged"
    \* means exactly "no write has landed since I read it", which is what
    \* If-Match tests in 11.2.
    visible = [kind |-> "multi", mid |-> InitId, by |-> "init"],

    \* The manifest sidecar objects that exist under .blindbucket/m/<hash>/.
    manifests = {InitId},

    \* Upstream multipart uploads that have been created and neither completed
    \* nor aborted.  This is what ListMultipartUploads reports in R4 step 2.
    openUploads = {},

    \* History variable, not part of the system: set when a rotation overwrites
    \* a version other than the one it read.  I2 is its negation.
    lostUpdate = FALSE;

define {
    VisibleMid == IF visible.kind = "multi" THEN visible.mid ELSE NoMid

    TypeOK ==
        /\ visible.kind \in Kinds
        /\ visible.mid  \in Mids \cup {NoMid}
        /\ visible.by   \in Writers
        /\ manifests   \subseteq Mids
        /\ openUploads \subseteq Uploads \cup {RotId}
        /\ lostUpdate  \in BOOLEAN

    \* I1 (10.8): every visible multipart object has its manifest.
    I1 == (visible.kind = "multi") => (visible.mid \in manifests)

    \* I2 (11.2): rotation causes no lost update.
    I2 == ~lostUpdate
}

(*************************************************************************)
(* A multipart upload, following the completion order of 10.6.  Every     *)
(* step may be the last one the process takes: the `or goto Done` branch  *)
(* is a crash of that proxy instance after the step before it.  Local     *)
(* state (the upload token, the observed manifest id) is lost; whatever   *)
(* the process already did at the upstream stays.                         *)
(*                                                                        *)
(* UploadPart and ListParts are omitted deliberately.  They neither read  *)
(* nor write any state this model has, so including them would only add   *)
(* interleavings that cannot change an outcome.                           *)
(*************************************************************************)
process (Up \in Uploads)
    variables observed = NoMid;
{
  upCreate:
    \* CreateMultipartUpload.  The manifest id is minted here (R1) and lives
    \* in the upload token, so it is fixed before any part is sent.
    either { openUploads := openUploads \cup {self}; }
    or     { goto Done; };

  upHead:
    \* Step 2: HEAD the key and remember the manifest id of whatever is
    \* visible right now.  This observation is what R3 later licenses a
    \* delete of -- and nothing else.
    either { observed := VisibleMid; }
    or     { goto Done; };

  upManifest:
    \* Step 3: write the manifest.  R2: before the object becomes visible,
    \* never after.  It does not disturb the currently visible object,
    \* because that object names a different manifest id.
    either { manifests := manifests \cup {self}; }
    or     { observed := NoMid; goto Done; };

  upComplete:
    \* Step 4: CompleteMultipartUpload.
    either {
        if (self \notin openUploads) {
            \* The lifecycle rule for incomplete uploads aborted this upload
            \* while the request was away.  Complete fails, the object does
            \* not become visible, and the manifest written at step 3 is now
            \* an orphan for gc to collect.
            observed := NoMid;
            goto Done;
        } else {
            openUploads := openUploads \ {self};
            visible := [kind |-> "multi", mid |-> self, by |-> self];
        };
    }
    or { observed := NoMid; goto Done; };

  upCleanup:
    \* Step 5, reached only when step 4 succeeded: delete the manifest of the
    \* version this upload replaced.
    either {
        if (CleanupMode = "v01") {
            \* Version 0.1: "delete all other manifests of this key".  This is
            \* the second race in 10.8 -- it reaches into manifests written by
            \* uploads that have not completed yet.
            manifests := manifests \cap {self};
        } else {
            \* R3: at most the one id observed at upHead, before this request's
            \* own replacement landed.  By R1 that id belongs to exactly one
            \* object version, and that version cannot become visible again.
            if (observed # NoMid) { manifests := manifests \ {observed}; };
        };
    }
    or { skip; };
    observed := NoMid;
}

(*************************************************************************)
(* A single-part PutObject.  It deliberately does not touch manifests: a  *)
(* PUT over a multipart object leaves an orphan behind for gc, which buys *)
(* one less HEAD on the most common write path (10.8).                    *)
(*************************************************************************)
process (Put = PutId)
{
  putWrite:
    either { visible := [kind |-> "single", mid |-> NoMid, by |-> PutId]; }
    or     { goto Done; };
}

(*************************************************************************)
(* DeleteObject.  Same shape as completion: observe, act, then delete the *)
(* manifest that was observed (R3).                                       *)
(*************************************************************************)
process (Del = DelId)
    variables delObserved = NoMid;
{
  delHead:
    either { delObserved := VisibleMid; }
    or     { goto Done; };

  delRemove:
    either { visible := [kind |-> "absent", mid |-> NoMid, by |-> DelId]; }
    or     { delObserved := NoMid; goto Done; };

  delManifest:
    either {
        if (delObserved # NoMid) { manifests := manifests \ {delObserved}; };
    }
    or { skip; };
    delObserved := NoMid;
}

(*************************************************************************)
(* `blindbucket rotate` on this key (11.2).  Rotation re-wraps the data   *)
(* key and copies the parts; single-part objects are rotated as a         *)
(* multipart upload with M = 1, so one shape covers both.  The copy gets  *)
(* a fresh manifest id (R1) and its own manifest, written before the      *)
(* completion (R2).                                                      *)
(*************************************************************************)
process (Rot = RotId)
    variables rotObserved = NoMid, rotSrcBy = "init";
{
  rotHead:
    either {
        if (RotateMode = "off" \/ visible.kind = "absent") {
            goto Done;    \* not configured, or nothing to rotate
        } else {
            rotObserved := VisibleMid;
            rotSrcBy    := visible.by;
        };
    }
    or { goto Done; };

  rotCreate:
    either { openUploads := openUploads \cup {RotId}; }
    or     { rotObserved := NoMid; rotSrcBy := "init"; goto Done; };

  rotManifest:
    either { manifests := manifests \cup {RotId}; }
    or     { rotObserved := NoMid; rotSrcBy := "init"; goto Done; };

  rotComplete:
    \* CompleteMultipartUpload carrying If-Match with the etag read at
    \* rotHead, so that a client write in between wins instead of being lost.
    either {
        if (RotId \notin openUploads) {
            \* aborted by the lifecycle rule
            rotObserved := NoMid; rotSrcBy := "init";
            goto Done;
        } else {
            if (RotateMode = "conditional" /\ visible.by # rotSrcBy) {
                \* 412 Precondition Failed: the object changed under us.
                \* rotate abandons the upload and reports the object skipped.
                openUploads := openUploads \ {RotId};
                rotObserved := NoMid; rotSrcBy := "init";
                goto Done;
            } else {
                if (visible.by # rotSrcBy) {
                    \* Only reachable with --allow-unconditional: the write
                    \* that landed in between has just been thrown away.
                    lostUpdate := TRUE;
                };
                openUploads := openUploads \ {RotId};
                visible := [kind |-> "multi", mid |-> RotId, by |-> RotId];
            };
        };
    }
    or { rotObserved := NoMid; rotSrcBy := "init"; goto Done; };

  rotCleanup:
    either {
        if (rotObserved # NoMid) { manifests := manifests \ {rotObserved}; };
    }
    or { skip; };
    rotObserved := NoMid;
    rotSrcBy := "init";
}

(*************************************************************************)
(* The bucket's lifecycle rule for incomplete multipart uploads (10.7).   *)
(* It may abort any open upload at any time, which is what makes a crash  *)
(* between upCreate and upComplete eventually visible to the model.       *)
(*                                                                       *)
(* The rule has no "done": when there is no open upload the action is     *)
(* simply disabled.  That is also why the configurations switch deadlock  *)
(* checking off -- every process reaching the end of its own code is a    *)
(* normal final state here, not a stuck system.                          *)
(*************************************************************************)
process (Life = "lifecycle")
{
  lifeAbort:
    while (TRUE) {
        with (u \in openUploads) { openUploads := openUploads \ {u}; };
    };
}

(*************************************************************************)
(* One `blindbucket gc` pass over this key, in the fixed order of R4.     *)
(* The minimum-age condition of R4 step 4 is not modelled: it is a guard  *)
(* against the upstream consistency assumptions failing, and this model   *)
(* assumes those hold.  What is modelled is the ordering argument, which  *)
(* is the part that was derived by reasoning and never checked.          *)
(*************************************************************************)
process (Gc = "gc")
    variables seen = {}, current = NoMid;
{
  gcStepOne:
    either {
        if (GcMode = "swapped") {
            \* ListMultipartUploads first -- see gcStepTwo.
            if (openUploads # {}) { goto Done; };
        } else {
            \* R4 step 1: list the manifests under this key's prefix.
            seen := manifests;
        };
    }
    or { goto Done; };

  gcStepTwo:
    either {
        if (GcMode = "swapped") {
            seen := manifests;
        } else {
            if (GcMode = "r4") {
                \* R4 step 2: an upload is in flight, so any manifest listed
                \* above may be about to become the current one.  Skip the key.
                if (openUploads # {}) { seen := {}; goto Done; };
            };
            \* GcMode = "v01" checked nothing here at all.
        };
    }
    or { seen := {}; goto Done; };

  gcHead:
    \* R4 step 3: HEAD the object for the manifest id in use right now.
    either { current := VisibleMid; }
    or     { seen := {}; goto Done; };

  gcDelete:
    \* R4 step 4: delete the listed manifests that are not the current one.
    either { manifests := manifests \ (seen \ {current}); }
    or     { skip; };
    seen := {};
    current := NoMid;
}

}
*)
\* BEGIN TRANSLATION
VARIABLES visible, manifests, openUploads, lostUpdate, pc

(* define statement *)
VisibleMid == IF visible.kind = "multi" THEN visible.mid ELSE NoMid

TypeOK ==
    /\ visible.kind \in Kinds
    /\ visible.mid  \in Mids \cup {NoMid}
    /\ visible.by   \in Writers
    /\ manifests   \subseteq Mids
    /\ openUploads \subseteq Uploads \cup {RotId}
    /\ lostUpdate  \in BOOLEAN


I1 == (visible.kind = "multi") => (visible.mid \in manifests)


I2 == ~lostUpdate

VARIABLES observed, delObserved, rotObserved, rotSrcBy, seen, current

vars == << visible, manifests, openUploads, lostUpdate, pc, observed, 
           delObserved, rotObserved, rotSrcBy, seen, current >>

ProcSet == (Uploads) \cup {PutId} \cup {DelId} \cup {RotId} \cup {"lifecycle"} \cup {"gc"}

Init == (* Global variables *)
        /\ visible = [kind |-> "multi", mid |-> InitId, by |-> "init"]
        /\ manifests = {InitId}
        /\ openUploads = {}
        /\ lostUpdate = FALSE
        (* Process Up *)
        /\ observed = [self \in Uploads |-> NoMid]
        (* Process Del *)
        /\ delObserved = NoMid
        (* Process Rot *)
        /\ rotObserved = NoMid
        /\ rotSrcBy = "init"
        (* Process Gc *)
        /\ seen = {}
        /\ current = NoMid
        /\ pc = [self \in ProcSet |-> CASE self \in Uploads -> "upCreate"
                                        [] self = PutId -> "putWrite"
                                        [] self = DelId -> "delHead"
                                        [] self = RotId -> "rotHead"
                                        [] self = "lifecycle" -> "lifeAbort"
                                        [] self = "gc" -> "gcStepOne"]

upCreate(self) == /\ pc[self] = "upCreate"
                  /\ \/ /\ openUploads' = (openUploads \cup {self})
                        /\ pc' = [pc EXCEPT ![self] = "upHead"]
                     \/ /\ pc' = [pc EXCEPT ![self] = "Done"]
                        /\ UNCHANGED openUploads
                  /\ UNCHANGED << visible, manifests, lostUpdate, observed, 
                                  delObserved, rotObserved, rotSrcBy, seen, 
                                  current >>

upHead(self) == /\ pc[self] = "upHead"
                /\ \/ /\ observed' = [observed EXCEPT ![self] = VisibleMid]
                      /\ pc' = [pc EXCEPT ![self] = "upManifest"]
                   \/ /\ pc' = [pc EXCEPT ![self] = "Done"]
                      /\ UNCHANGED observed
                /\ UNCHANGED << visible, manifests, openUploads, lostUpdate, 
                                delObserved, rotObserved, rotSrcBy, seen, 
                                current >>

upManifest(self) == /\ pc[self] = "upManifest"
                    /\ \/ /\ manifests' = (manifests \cup {self})
                          /\ pc' = [pc EXCEPT ![self] = "upComplete"]
                          /\ UNCHANGED observed
                       \/ /\ observed' = [observed EXCEPT ![self] = NoMid]
                          /\ pc' = [pc EXCEPT ![self] = "Done"]
                          /\ UNCHANGED manifests
                    /\ UNCHANGED << visible, openUploads, lostUpdate, 
                                    delObserved, rotObserved, rotSrcBy, seen, 
                                    current >>

upComplete(self) == /\ pc[self] = "upComplete"
                    /\ \/ /\ IF self \notin openUploads
                                THEN /\ observed' = [observed EXCEPT ![self] = NoMid]
                                     /\ pc' = [pc EXCEPT ![self] = "Done"]
                                     /\ UNCHANGED << visible, openUploads >>
                                ELSE /\ openUploads' = openUploads \ {self}
                                     /\ visible' = [kind |-> "multi", mid |-> self, by |-> self]
                                     /\ pc' = [pc EXCEPT ![self] = "upCleanup"]
                                     /\ UNCHANGED observed
                       \/ /\ observed' = [observed EXCEPT ![self] = NoMid]
                          /\ pc' = [pc EXCEPT ![self] = "Done"]
                          /\ UNCHANGED <<visible, openUploads>>
                    /\ UNCHANGED << manifests, lostUpdate, delObserved, 
                                    rotObserved, rotSrcBy, seen, current >>

upCleanup(self) == /\ pc[self] = "upCleanup"
                   /\ \/ /\ IF CleanupMode = "v01"
                               THEN /\ manifests' = (manifests \cap {self})
                               ELSE /\ IF observed[self] # NoMid
                                          THEN /\ manifests' = manifests \ {observed[self]}
                                          ELSE /\ TRUE
                                               /\ UNCHANGED manifests
                      \/ /\ TRUE
                         /\ UNCHANGED manifests
                   /\ observed' = [observed EXCEPT ![self] = NoMid]
                   /\ pc' = [pc EXCEPT ![self] = "Done"]
                   /\ UNCHANGED << visible, openUploads, lostUpdate, 
                                   delObserved, rotObserved, rotSrcBy, seen, 
                                   current >>

Up(self) == upCreate(self) \/ upHead(self) \/ upManifest(self)
               \/ upComplete(self) \/ upCleanup(self)

putWrite == /\ pc[PutId] = "putWrite"
            /\ \/ /\ visible' = [kind |-> "single", mid |-> NoMid, by |-> PutId]
                  /\ pc' = [pc EXCEPT ![PutId] = "Done"]
               \/ /\ pc' = [pc EXCEPT ![PutId] = "Done"]
                  /\ UNCHANGED visible
            /\ UNCHANGED << manifests, openUploads, lostUpdate, observed, 
                            delObserved, rotObserved, rotSrcBy, seen, current >>

Put == putWrite

delHead == /\ pc[DelId] = "delHead"
           /\ \/ /\ delObserved' = VisibleMid
                 /\ pc' = [pc EXCEPT ![DelId] = "delRemove"]
              \/ /\ pc' = [pc EXCEPT ![DelId] = "Done"]
                 /\ UNCHANGED delObserved
           /\ UNCHANGED << visible, manifests, openUploads, lostUpdate, 
                           observed, rotObserved, rotSrcBy, seen, current >>

delRemove == /\ pc[DelId] = "delRemove"
             /\ \/ /\ visible' = [kind |-> "absent", mid |-> NoMid, by |-> DelId]
                   /\ pc' = [pc EXCEPT ![DelId] = "delManifest"]
                   /\ UNCHANGED delObserved
                \/ /\ delObserved' = NoMid
                   /\ pc' = [pc EXCEPT ![DelId] = "Done"]
                   /\ UNCHANGED visible
             /\ UNCHANGED << manifests, openUploads, lostUpdate, observed, 
                             rotObserved, rotSrcBy, seen, current >>

delManifest == /\ pc[DelId] = "delManifest"
               /\ \/ /\ IF delObserved # NoMid
                           THEN /\ manifests' = manifests \ {delObserved}
                           ELSE /\ TRUE
                                /\ UNCHANGED manifests
                  \/ /\ TRUE
                     /\ UNCHANGED manifests
               /\ delObserved' = NoMid
               /\ pc' = [pc EXCEPT ![DelId] = "Done"]
               /\ UNCHANGED << visible, openUploads, lostUpdate, observed, 
                               rotObserved, rotSrcBy, seen, current >>

Del == delHead \/ delRemove \/ delManifest

rotHead == /\ pc[RotId] = "rotHead"
           /\ \/ /\ IF RotateMode = "off" \/ visible.kind = "absent"
                       THEN /\ pc' = [pc EXCEPT ![RotId] = "Done"]
                            /\ UNCHANGED << rotObserved, rotSrcBy >>
                       ELSE /\ rotObserved' = VisibleMid
                            /\ rotSrcBy' = visible.by
                            /\ pc' = [pc EXCEPT ![RotId] = "rotCreate"]
              \/ /\ pc' = [pc EXCEPT ![RotId] = "Done"]
                 /\ UNCHANGED <<rotObserved, rotSrcBy>>
           /\ UNCHANGED << visible, manifests, openUploads, lostUpdate, 
                           observed, delObserved, seen, current >>

rotCreate == /\ pc[RotId] = "rotCreate"
             /\ \/ /\ openUploads' = (openUploads \cup {RotId})
                   /\ pc' = [pc EXCEPT ![RotId] = "rotManifest"]
                   /\ UNCHANGED <<rotObserved, rotSrcBy>>
                \/ /\ rotObserved' = NoMid
                   /\ rotSrcBy' = "init"
                   /\ pc' = [pc EXCEPT ![RotId] = "Done"]
                   /\ UNCHANGED openUploads
             /\ UNCHANGED << visible, manifests, lostUpdate, observed, 
                             delObserved, seen, current >>

rotManifest == /\ pc[RotId] = "rotManifest"
               /\ \/ /\ manifests' = (manifests \cup {RotId})
                     /\ pc' = [pc EXCEPT ![RotId] = "rotComplete"]
                     /\ UNCHANGED <<rotObserved, rotSrcBy>>
                  \/ /\ rotObserved' = NoMid
                     /\ rotSrcBy' = "init"
                     /\ pc' = [pc EXCEPT ![RotId] = "Done"]
                     /\ UNCHANGED manifests
               /\ UNCHANGED << visible, openUploads, lostUpdate, observed, 
                               delObserved, seen, current >>

rotComplete == /\ pc[RotId] = "rotComplete"
               /\ \/ /\ IF RotId \notin openUploads
                           THEN /\ rotObserved' = NoMid
                                /\ rotSrcBy' = "init"
                                /\ pc' = [pc EXCEPT ![RotId] = "Done"]
                                /\ UNCHANGED << visible, openUploads, 
                                                lostUpdate >>
                           ELSE /\ IF RotateMode = "conditional" /\ visible.by # rotSrcBy
                                      THEN /\ openUploads' = openUploads \ {RotId}
                                           /\ rotObserved' = NoMid
                                           /\ rotSrcBy' = "init"
                                           /\ pc' = [pc EXCEPT ![RotId] = "Done"]
                                           /\ UNCHANGED << visible, lostUpdate >>
                                      ELSE /\ IF visible.by # rotSrcBy
                                                 THEN /\ lostUpdate' = TRUE
                                                 ELSE /\ TRUE
                                                      /\ UNCHANGED lostUpdate
                                           /\ openUploads' = openUploads \ {RotId}
                                           /\ visible' = [kind |-> "multi", mid |-> RotId, by |-> RotId]
                                           /\ pc' = [pc EXCEPT ![RotId] = "rotCleanup"]
                                           /\ UNCHANGED << rotObserved, 
                                                           rotSrcBy >>
                  \/ /\ rotObserved' = NoMid
                     /\ rotSrcBy' = "init"
                     /\ pc' = [pc EXCEPT ![RotId] = "Done"]
                     /\ UNCHANGED <<visible, openUploads, lostUpdate>>
               /\ UNCHANGED << manifests, observed, delObserved, seen, current >>

rotCleanup == /\ pc[RotId] = "rotCleanup"
              /\ \/ /\ IF rotObserved # NoMid
                          THEN /\ manifests' = manifests \ {rotObserved}
                          ELSE /\ TRUE
                               /\ UNCHANGED manifests
                 \/ /\ TRUE
                    /\ UNCHANGED manifests
              /\ rotObserved' = NoMid
              /\ rotSrcBy' = "init"
              /\ pc' = [pc EXCEPT ![RotId] = "Done"]
              /\ UNCHANGED << visible, openUploads, lostUpdate, observed, 
                              delObserved, seen, current >>

Rot == rotHead \/ rotCreate \/ rotManifest \/ rotComplete \/ rotCleanup

lifeAbort == /\ pc["lifecycle"] = "lifeAbort"
             /\ \E u \in openUploads:
                  openUploads' = openUploads \ {u}
             /\ pc' = [pc EXCEPT !["lifecycle"] = "lifeAbort"]
             /\ UNCHANGED << visible, manifests, lostUpdate, observed, 
                             delObserved, rotObserved, rotSrcBy, seen, current >>

Life == lifeAbort

gcStepOne == /\ pc["gc"] = "gcStepOne"
             /\ \/ /\ IF GcMode = "swapped"
                         THEN /\ IF openUploads # {}
                                    THEN /\ pc' = [pc EXCEPT !["gc"] = "Done"]
                                    ELSE /\ pc' = [pc EXCEPT !["gc"] = "gcStepTwo"]
                              /\ seen' = seen
                         ELSE /\ seen' = manifests
                              /\ pc' = [pc EXCEPT !["gc"] = "gcStepTwo"]
                \/ /\ pc' = [pc EXCEPT !["gc"] = "Done"]
                   /\ seen' = seen
             /\ UNCHANGED << visible, manifests, openUploads, lostUpdate, 
                             observed, delObserved, rotObserved, rotSrcBy, 
                             current >>

gcStepTwo == /\ pc["gc"] = "gcStepTwo"
             /\ \/ /\ IF GcMode = "swapped"
                         THEN /\ seen' = manifests
                              /\ pc' = [pc EXCEPT !["gc"] = "gcHead"]
                         ELSE /\ IF GcMode = "r4"
                                    THEN /\ IF openUploads # {}
                                               THEN /\ seen' = {}
                                                    /\ pc' = [pc EXCEPT !["gc"] = "Done"]
                                               ELSE /\ pc' = [pc EXCEPT !["gc"] = "gcHead"]
                                                    /\ seen' = seen
                                    ELSE /\ pc' = [pc EXCEPT !["gc"] = "gcHead"]
                                         /\ seen' = seen
                \/ /\ seen' = {}
                   /\ pc' = [pc EXCEPT !["gc"] = "Done"]
             /\ UNCHANGED << visible, manifests, openUploads, lostUpdate, 
                             observed, delObserved, rotObserved, rotSrcBy, 
                             current >>

gcHead == /\ pc["gc"] = "gcHead"
          /\ \/ /\ current' = VisibleMid
                /\ pc' = [pc EXCEPT !["gc"] = "gcDelete"]
                /\ seen' = seen
             \/ /\ seen' = {}
                /\ pc' = [pc EXCEPT !["gc"] = "Done"]
                /\ UNCHANGED current
          /\ UNCHANGED << visible, manifests, openUploads, lostUpdate, 
                          observed, delObserved, rotObserved, rotSrcBy >>

gcDelete == /\ pc["gc"] = "gcDelete"
            /\ \/ /\ manifests' = manifests \ (seen \ {current})
               \/ /\ TRUE
                  /\ UNCHANGED manifests
            /\ seen' = {}
            /\ current' = NoMid
            /\ pc' = [pc EXCEPT !["gc"] = "Done"]
            /\ UNCHANGED << visible, openUploads, lostUpdate, observed, 
                            delObserved, rotObserved, rotSrcBy >>

Gc == gcStepOne \/ gcStepTwo \/ gcHead \/ gcDelete

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == Put \/ Del \/ Rot \/ Life \/ Gc
           \/ (\E self \in Uploads: Up(self))
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

=============================================================================
