use machineid_rs::{Encryption, HWIDComponent, IdBuilder};

pub fn get_machine_id() -> String {
    // There are 3 different encryption types: MD5, SHA1 and SHA256.

    let mut builder = IdBuilder::new(Encryption::SHA256);
    builder
        .add_component(HWIDComponent::SystemID)
        .add_component(HWIDComponent::CPUCores)
        .add_component(HWIDComponent::MacAddress);
    return builder.build("gsc!").unwrap();
    // "".to_string()
}
