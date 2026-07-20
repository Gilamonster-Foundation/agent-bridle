def moduleName (path : System.FilePath) : String :=
  let components := path.components.filter fun component => component != "."
  String.intercalate "." <| components.map fun component =>
    if component.endsWith ".lean" then (component.dropEnd 5).copy else component

def hasDirectImport (rootSource module : String) : Bool :=
  (rootSource.splitOn "\n").any fun line =>
    line.trimAscii.copy == s!"import {module}"

def proofEscapeErrors
    (path : System.FilePath) (source : String) : Array String := Id.run do
  let forbidden := #["sor" ++ "ry", "ad" ++ "mit", "ax" ++ "iom"]
  let mut errors := #[]
  for word in forbidden do
    if source.contains word then
      errors := errors.push s!"{path}: forbidden proof escape `{word}`"
  return errors

def isFormalRoot (module : String) : Bool :=
  module == "Ceremony" || module == "Tests" || module == "Gate"
    || module == "AxiomAudit"

def main : IO Unit := do
  let ceremonyRoot <- IO.FS.readFile "Ceremony.lean"
  let testsRoot <- IO.FS.readFile "Tests.lean"
  let mut errors := #[]
  -- `refinement/` is a SEPARATE, heavy Lake project (Aeneas + mathlib + Aeneas-
  -- generated code that legitimately uses opaque externals, plus a machine-local
  -- `aeneas-lean` symlink into the Aeneas source). It is gated on its own by
  -- `just check-refinement`, NOT by this fast mathlib-free gate — so prune it.
  -- (This comment avoids the literal escape words on purpose — the gate scans
  -- its own source too.)
  let paths <- (System.FilePath.mk ".").walkDir fun path =>
    pure (!path.components.contains ".lake" && !path.components.contains "refinement")
  for path in paths do
    if path.extension == some "lean" && !path.components.contains ".lake" then
      let source <- IO.FS.readFile path
      errors := errors ++ proofEscapeErrors path source
      let module := moduleName path
      if !isFormalRoot module &&
          !hasDirectImport ceremonyRoot module &&
          !hasDirectImport testsRoot module then
        errors := errors.push
          s!"{path}: `{module}` is absent from Ceremony.lean and Tests.lean"
  if errors.isEmpty then
    IO.println "formal gate: all Lean sources and root imports verified"
  else
    for error in errors do
      IO.eprintln s!"formal gate: {error}"
    throw <| IO.userError s!"formal gate rejected {errors.size} violation(s)"
