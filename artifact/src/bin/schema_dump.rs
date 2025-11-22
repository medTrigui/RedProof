use redproof_artifact::RedProofArtifact;

fn main() {
    let schema = schemars::schema_for!(RedProofArtifact);
    let json = serde_json::to_string_pretty(&schema).expect("schema json");
    println!("{}", json);
}
