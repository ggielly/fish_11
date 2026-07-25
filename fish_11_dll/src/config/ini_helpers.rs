use std::collections::HashMap;

use ini::Ini;

use super::models::{EntryData, Fish11Section, FishConfig, StartupSection};

pub fn parse_bool(value: &str) -> bool {
    value.eq_ignore_ascii_case("true") || value == "1"
}

pub fn parse_i64(value: &str) -> Option<i64> {
    value.parse().ok()
}

pub fn load_keypair(
    ini: &Ini,
    sections: &HashMap<String, String>,
) -> (Option<String>, Option<String>) {
    let mut private = None;
    let mut public = None;
    if let Some(section) = sections.get("keypair") {
        if let Some(v) = ini.get_from(Some(section), "private") {
            private = Some(v.to_string());
        }
        if let Some(v) = ini.get_from(Some(section), "public") {
            public = Some(v.to_string());
        }
    }
    (private, public)
}

pub fn save_keypair(ini: &mut Ini, private: &Option<String>, public: &Option<String>) {
    if let Some(p) = private {
        ini.with_section(Some("KeyPair")).set("private", p.as_str());
    }
    if let Some(p) = public {
        ini.with_section(Some("KeyPair")).set("public", p.as_str());
    }
}

pub fn load_nick_networks(
    ini: &Ini,
    sections: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(section) = sections.get("nicknetworks") {
        if let Some(s) = ini.section(Some(section.as_str())) {
            for (k, v) in s.iter() {
                map.insert(k.to_string(), v.to_string());
            }
        }
    }
    map
}

pub fn save_nick_networks(ini: &mut Ini, nick_networks: &HashMap<String, String>) {
    let mut sorted: Vec<(&String, &String)> = nick_networks.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (k, v) in sorted {
        ini.with_section(Some("NickNetworks")).set(k.as_str(), v.as_str());
    }
}

pub fn load_fish11_section(ini: &Ini, sections: &HashMap<String, String>) -> Fish11Section {
    let mut fish11 = Fish11Section::default();
    if let Some(section) = sections.get("fish11") {
        if let Some(v) = ini.get_from(Some(section), "process_incoming") {
            fish11.process_incoming = parse_bool(v);
        }
        if let Some(v) = ini.get_from(Some(section), "process_outgoing") {
            fish11.process_outgoing = parse_bool(v);
        }
        if let Some(v) = ini.get_from(Some(section), "plain_prefix") {
            fish11.plain_prefix = v.to_string();
        }
        if let Some(v) = ini.get_from(Some(section), "encrypt_notice") {
            fish11.encrypt_notice = parse_bool(v);
        }
        if let Some(v) = ini.get_from(Some(section), "encrypt_action") {
            fish11.encrypt_action = parse_bool(v);
        }
        if let Some(v) = ini.get_from(Some(section), "mark_position") {
            if let Some(pos) = parse_i64(v) {
                fish11.mark_position = pos as u8;
            }
        }
        if let Some(v) = ini.get_from(Some(section), "mark_encrypted") {
            fish11.mark_encrypted = v.to_string();
        }
        if let Some(v) = ini.get_from(Some(section), "no_fish10_legacy") {
            fish11.no_fish10_legacy = parse_bool(v);
        }
        if let Some(v) = ini.get_from(Some(section), "key_ttl") {
            if let Some(ttl) = parse_i64(v) {
                fish11.key_ttl = Some(ttl);
            }
        }
        if let Some(v) = ini.get_from(Some(section), "encryption_prefix") {
            fish11.encryption_prefix = v.to_string();
        }
        if let Some(v) = ini.get_from(Some(section), "fish_prefix") {
            fish11.fish_prefix = parse_bool(v);
        }
    }
    fish11
}

pub fn save_fish11_section(ini: &mut Ini, fish11: &Fish11Section) {
    ini.with_section(Some("FiSH11"))
        .set("process_incoming", fish11.process_incoming.to_string().as_str())
        .set("process_outgoing", fish11.process_outgoing.to_string().as_str())
        .set("plain_prefix", fish11.plain_prefix.as_str())
        .set("encrypt_notice", fish11.encrypt_notice.to_string().as_str())
        .set("encrypt_action", fish11.encrypt_action.to_string().as_str())
        .set("mark_position", fish11.mark_position.to_string().as_str())
        .set("mark_encrypted", fish11.mark_encrypted.as_str())
        .set("no_fish10_legacy", fish11.no_fish10_legacy.to_string().as_str());

    if let Some(ttl) = fish11.key_ttl {
        ini.with_section(Some("FiSH11")).set("key_ttl", ttl.to_string().as_str());
    }

    ini.with_section(Some("FiSH11"))
        .set("encryption_prefix", fish11.encryption_prefix.as_str())
        .set("fish_prefix", fish11.fish_prefix.to_string().as_str());
}

pub fn load_startup(ini: &Ini, sections: &HashMap<String, String>) -> StartupSection {
    let mut startup = StartupSection::default();
    if let Some(section) = sections.get("startup") {
        if let Some(v) = ini.get_from(Some(section), "date") {
            if let Some(d) = parse_i64(v) {
                startup.date = Some(d as u64);
            }
        }
    }
    startup
}

pub fn save_startup(ini: &mut Ini, startup: &StartupSection) {
    if let Some(date) = startup.date {
        ini.with_section(Some("Startup")).set("date", date.to_string().as_str());
    }
}

pub fn load_entries(ini: &Ini, sections: &HashMap<String, String>) -> HashMap<String, EntryData> {
    let mut entries = HashMap::new();
    let keys_section = sections.get("keys");
    let dates_section = sections.get("dates");

    if let Some(keys_name) = keys_section {
        if let Some(keys_data) = ini.section(Some(keys_name.as_str())) {
            let dates_data = dates_section.and_then(|n| ini.section(Some(n.as_str())));
            for (entry_key, key_val) in keys_data.iter() {
                let date_val = dates_data.and_then(|d| d.get(entry_key).map(|s| s.to_string()));
                entries.insert(
                    entry_key.to_string(),
                    EntryData {
                        key: Some(key_val.to_string()),
                        date: date_val,
                        is_exchange: Some(false),
                    },
                );
            }
        }
    }
    entries
}

pub fn save_entries(ini: &mut Ini, entries: &HashMap<String, EntryData>) {
    let mut sorted: Vec<(&String, &EntryData)> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (entry_key, entry_data) in sorted {
        if let Some(key_val) = &entry_data.key {
            ini.with_section(Some("Keys")).set(entry_key.as_str(), key_val.as_str());
        }
        if let Some(date_val) = &entry_data.date {
            ini.with_section(Some("Dates")).set(entry_key.as_str(), date_val.as_str());
        }
    }
}

pub fn build_section_cache(ini: &Ini) -> HashMap<String, String> {
    ini.sections().filter_map(|s| s.map(|s| (s.to_lowercase(), s.to_string()))).collect()
}

pub fn config_to_ini(config: &FishConfig) -> Ini {
    let mut ini = Ini::new();
    save_keypair(&mut ini, &config.our_private_key, &config.our_public_key);
    save_nick_networks(&mut ini, &config.nick_networks);
    save_fish11_section(&mut ini, &config.fish11);
    save_startup(&mut ini, &config.startup_data);
    save_entries(&mut ini, &config.entries);
    ini
}

pub fn ini_to_config(ini: &Ini) -> FishConfig {
    let sections = build_section_cache(ini);
    let (private, public) = load_keypair(ini, &sections);
    let nick_networks = load_nick_networks(ini, &sections);
    let fish11 = load_fish11_section(ini, &sections);
    let startup = load_startup(ini, &sections);
    let entries = load_entries(ini, &sections);

    let mut config = FishConfig::new();
    config.our_private_key = private;
    config.our_public_key = public;
    config.nick_networks = nick_networks;
    config.fish11 = fish11;
    config.startup_data = startup;
    config.entries = entries;
    config
}
