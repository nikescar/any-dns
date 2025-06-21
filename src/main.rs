mod custom_handler;
mod dns_socket;
mod pending_request;
mod query_id_manager;
mod server;
mod args;
mod show;
mod cli_options;
mod protocol;

use dnslib::dns::rfc::{qtype::QType};
use dnslib::dns::message::MessageList;
use dnslib::error::Error::Tokio;
use dnslib::transport::{
    https::HttpsProtocol,
    network::{Messenger, Protocol},
    quic::QuicProtocol,
    tcp::TcpProtocol,
    tls::TlsProtocol,
    udp::UdpProtocol,
};
use std::collections::BTreeSet;
use std::{error::Error, net::Ipv4Addr};
use std::borrow::Cow;
use std::net::Ipv6Addr;
use custom_handler::{CustomHandler, CustomHandlerError };
use server::{Builder};
use dns_socket::{DnsSocket};

use async_trait::async_trait;
use dnslib::dns::rfc::domain::DomainName;
use simple_dns::{CharacterString, Name, Packet, ResourceRecord, QTYPE, TYPE};
use simple_dns::rdata::{A, AAAA, NS, MD, CNAME, MB, MG, MR, PTR, MF, HINFO, MINFO, MX, TXT, SOA, WKS, SRV, RP, AFSDB, ISDN, RouteThrough, NAPTR, NSAP, NSAP_PTR, LOC, OPT, CAA, SVCB, HTTPS, EUI48, EUI64, CERT, ZONEMD, KX, IPSECKEY, DNSKEY, RRSIG, DS, NSEC, DHCID};

use crate::args::CliOptions;
use crate::protocol::DnsProtocol;
use crate::show::QueryInfo;

#[derive(Clone, Debug)]
struct MyHandler {
    pub options: CliOptions,
    pub info: QueryInfo,
}

const BUFFER_SIZE: usize = 8192;

#[async_trait]
impl CustomHandler for MyHandler {
    /**
     * Only resolve 1 custom domain any.dns.
     */
    async fn lookup(
        &mut self,
        query: &Vec<u8>,
        _socket: DnsSocket,
    ) -> Result<Vec<u8>, CustomHandlerError> {
        // query from server socket
        // Parse query with any dns library. Here, we use `simple_dns``.
        let packet = Packet::parse(query).unwrap();
        let mut question = packet.questions.get(0).expect("Valid query");
        let mut cantranslate = false;

        self.options.protocol.qtype.clear();
        // ORDER BY SIMPLE_DNS RDATA TYPES
        // https://github.com/balliegojr/simple-dns/blob/2193a4a05e2ae52b2018b6c9691c28a65591e268/simple-dns/src/dns/rdata/mod.rs#L165
        // https://github.com/dandyvica/dqy/blob/c2b28be3d185360f9e94a92da95d318c08db9926/src/dns/rfc/mod.rs#L20
        // https://github.com/dandyvica/dqy/tree/main/src/dns/rfc
        // not implemented in simple_dns
        // algorithm apl csync hip nsec3 nsec3param openpgpkey query rdata response
        // rrlist sshfp tlsa type_bitmaps uri wallet
        if question.qtype == QTYPE::TYPE(TYPE::A){ // simple_dns supports
            self.options.protocol.qtype.push(QType::A);
            cantranslate = true; // dqy supports => true, simple_dns supports => false
        }
        if question.qtype == QTYPE::TYPE(TYPE::AAAA){
            self.options.protocol.qtype.push(QType::AAAA);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::NS){ 
            self.options.protocol.qtype.push(QType::NS);
            cantranslate = true;  // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::MD){ 
            self.options.protocol.qtype.push(QType::MD);
            cantranslate = false;
        }
        if question.qtype == QTYPE::TYPE(TYPE::CNAME){ 
            self.options.protocol.qtype.push(QType::CNAME);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::MB){ 
            self.options.protocol.qtype.push(QType::MB);
            cantranslate = false;
        }
        if question.qtype == QTYPE::TYPE(TYPE::MG){ 
            self.options.protocol.qtype.push(QType::MG);
            cantranslate = false;
        }
        if question.qtype == QTYPE::TYPE(TYPE::MR){ 
            self.options.protocol.qtype.push(QType::MR);
            cantranslate = false;
        }
        if question.qtype == QTYPE::TYPE(TYPE::PTR){ 
            self.options.protocol.qtype.push(QType::PTR);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::MF){ 
            self.options.protocol.qtype.push(QType::MF);
            cantranslate = false;
        }
        if question.qtype == QTYPE::TYPE(TYPE::HINFO){ 
            self.options.protocol.qtype.push(QType::HINFO);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::MINFO){ 
            self.options.protocol.qtype.push(QType::MINFO);
            cantranslate = false;
        }
        if question.qtype == QTYPE::TYPE(TYPE::MX){
            self.options.protocol.qtype.push(QType::MX);
            cantranslate = true;  // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::TXT){ 
            self.options.protocol.qtype.push(QType::TXT);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::SOA){ 
            self.options.protocol.qtype.push(QType::SOA);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::WKS){ 
            self.options.protocol.qtype.push(QType::WKS);
            cantranslate = false;
        }
        if question.qtype == QTYPE::TYPE(TYPE::SRV){ 
            self.options.protocol.qtype.push(QType::SRV);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::RP){ 
            self.options.protocol.qtype.push(QType::RP);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::AFSDB){ 
            self.options.protocol.qtype.push(QType::AFSDB);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::ISDN){ 
            self.options.protocol.qtype.push(QType::ISDN);
            cantranslate = false;
        }
        // if question.qtype == QTYPE::TYPE(TYPE::RouteThrough){ // ** not exists **
        //     self.options.protocol.qtype.push(QType::RouteThrough);
        //     cantranslate = false;
        // }
        if question.qtype == QTYPE::TYPE(TYPE::NAPTR){ 
            self.options.protocol.qtype.push(QType::NAPTR);
            cantranslate = true;  // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::NSAP){ 
            self.options.protocol.qtype.push(QType::NSAP);
            cantranslate = false;
        }
        if question.qtype == QTYPE::TYPE(TYPE::NSAP_PTR){ 
            self.options.protocol.qtype.push(QType::NSAPPTR);
            cantranslate = false;
        }
        if question.qtype == QTYPE::TYPE(TYPE::LOC){ 
            self.options.protocol.qtype.push(QType::LOC);
            cantranslate = true;  // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::OPT){
            self.options.protocol.qtype.push(QType::OPT);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::CAA){ 
            self.options.protocol.qtype.push(QType::CAA);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::SVCB){ 
            self.options.protocol.qtype.push(QType::SVCB);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::HTTPS){ 
            self.options.protocol.qtype.push(QType::HTTPS);
            cantranslate = true; // *********************
        }
        if question.qtype == QTYPE::TYPE(TYPE::EUI48){
            self.options.protocol.qtype.push(QType::EUI48);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::EUI64){
            self.options.protocol.qtype.push(QType::EUI64);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::CERT){
            self.options.protocol.qtype.push(QType::CERT);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::ZONEMD){
            self.options.protocol.qtype.push(QType::ZONEMD);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::KX){
            self.options.protocol.qtype.push(QType::KX);
            cantranslate = true;  // dqy supports => true
        } 
        if question.qtype == QTYPE::TYPE(TYPE::IPSECKEY){
            self.options.protocol.qtype.push(QType::IPSECKEY);
            cantranslate = true;  // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::DNSKEY){
            self.options.protocol.qtype.push(QType::DNSKEY);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::RRSIG){
            self.options.protocol.qtype.push(QType::RRSIG);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::DS){
            self.options.protocol.qtype.push(QType::DS);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::NSEC){
            self.options.protocol.qtype.push(QType::NSEC);
            cantranslate = true; // dqy supports => true
        }
        if question.qtype == QTYPE::TYPE(TYPE::DHCID){
            self.options.protocol.qtype.push(QType::DHCID);
            cantranslate = true; // dqy supports => true
        }
        // if question.qtype == QTYPE::TYPE(TYPE::NSEC3){
        //     self.options.protocol.qtype.push(QType::NSEC3)
        //     cantranslate = true;
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::NSEC3PARAM){
        //     self.options.protocol.qtype.push(QType::NSEC3PARAM)
        //     cantranslate = true;
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::OPENPGPKEY){ 
        //     self.options.protocol.qtype.push(QType::OPENPGPKEY);
        //     cantranslate = true;
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::SSHFP){ 
        //     self.options.protocol.qtype.push(QType::SSHFP);
        //     cantranslate = true;
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::TLSA){
        //     self.options.protocol.qtype.push(QType::TLSA);
        //     cantranslate = true;
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::URI){
        //     self.options.protocol.qtype.push(QType::URI);
        //     cantranslate = true;
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::WALLET){
        //     self.options.protocol.qtype.push(QType::WALLET);
        //     cantranslate = true;
        // }
        
        self.options.protocol.domain_string = question.qname.to_string();
        self.options.protocol.domain_name = DomainName::try_from(self.options.protocol.domain_string.as_str()).expect("REASON");
        tracing::debug!("qtype : {:?}", question.qtype.clone());
        tracing::debug!("query name : {}",question.qname.to_string());
        tracing::debug!("cantranslate : {}",cantranslate);
        if cantranslate {
            Ok(self.construct_reply_dqy(query).await) // Reply with A record IP
        } else {
            tracing::debug!("fallback to ICANN DNS");
            Err(CustomHandlerError::Unhandled) // Fallback to ICANN
        }
    }
}

impl MyHandler {
    pub fn new() -> Self {
        Self {
            options: CliOptions::default(),
            info: QueryInfo::default()
        }
    }

    // Construct reply from dqy MessageList
    async fn construct_reply_dqy(&self, query: &Vec<u8>) -> Vec<u8> {
        let packet = Packet::parse(query).unwrap();
        let question = packet.questions.get(0).expect("Valid query");
        let messages = self.get_messages(self.info.clone(), &self.options).await;

        let messagestr = messages.unwrap();

        tracing::debug!("messagestr : {}",messagestr);
        let mut reply = Packet::new_reply(packet.id());
        reply.questions.push(question.clone());
        if messagestr.len() == 0 {
            reply.build_bytes_vec().unwrap()
        }else{
            let rsvtext = messagestr.to_string();
            let mut lines = rsvtext.lines();
            lines.next(); // Skip firstline : QUERY
            let mut index=0;
            loop {
                let mut cline: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
                let mut msgparts = Vec::new();
                if index == 0 {
                    if cline.len() > 12 {
                        msgparts = cline.split_off(12);
                        if !msgparts.is_empty() && msgparts[0].starts_with("0))") {
                            msgparts[0] = &msgparts[0][3..];
                        }
                    }
                } else {
                    msgparts = cline;
                }
                tracing::debug!("[{:?}]msgparts : {:?}", index, msgparts);

                if msgparts[0] == "." {
                    return reply.build_bytes_vec().unwrap();
                }

                match msgparts[1] {
                    "A" => {
                        let domain = Name::new(msgparts[0]).unwrap();
                        let nstype = Name::new(msgparts[1]).unwrap();
                        let mut value: String = msgparts[5].to_string();
                        let rdata: Ipv4Addr = value.parse().unwrap();
                        reply.answers.push(ResourceRecord::new(
                            domain,
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::A(rdata.try_into().unwrap()),
                        ));
                    }
                    "AAAA" => {
                        let domain = Name::new(msgparts[0]).unwrap();
                        let nstype = Name::new(msgparts[1]).unwrap();
                        let mut value: String = msgparts[5].to_string();
                        let rdata: Ipv6Addr = value.parse().unwrap();
                        reply.answers.push(ResourceRecord::new(
                            domain,
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::AAAA(rdata.try_into().unwrap()),
                        ));
                    }
                    "NS" => {
                        let domain = Name::new(msgparts[0]).unwrap();
                        let nstype = Name::new(msgparts[1]).unwrap();
                        let target = Name::new(msgparts[5]).unwrap();
                        let eta = msgparts[3].to_string();
                        reply.answers.push(ResourceRecord::new(
                            domain,
                            simple_dns::CLASS::IN,
                            eta.parse().unwrap_or(120),
                            simple_dns::rdata::RData::NS(simple_dns::rdata::NS::from(target))
                        ));
                    }
                    "CNAME" => {
                        let cname = Name::new(msgparts[5]).unwrap();
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::CNAME(simple_dns::rdata::CNAME::from(cname)),
                        ));
                    }
                    "PTR" => {
                        let ptrdname = Name::new(msgparts[5]).unwrap();
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::PTR(simple_dns::rdata::PTR::from(ptrdname)),
                        ));
                    }
                    "HINFO" => {
                        let ptrdname = Name::new(msgparts[5]).unwrap();
                        let cpu = msgparts.get(6).unwrap_or(&"");
                        let os = msgparts.get(7).unwrap_or(&"");
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::HINFO(simple_dns::rdata::HINFO {
                                cpu: simple_dns::CharacterString::try_from(cpu.to_string()).unwrap(),
                                os: simple_dns::CharacterString::try_from(os.to_string()).unwrap(),
                            }),
                        ));
                    }
                    "MX" => {
                        let preference: u16 = msgparts[5].parse().unwrap();
                        let exchange = Name::new(msgparts[6]).unwrap();
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::MX(simple_dns::rdata::MX { preference, exchange }),
                        ));
                    }
                    "TXT" => {
                        let domain = Name::new(msgparts[0]).unwrap();
                        let txtrecord = TXT::new().with_string(msgparts[5]).unwrap();
                        let nstype = Name::new(msgparts[1]).unwrap();
                        let eta = msgparts[3].to_string();
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            eta.parse().unwrap_or(120),
                            simple_dns::rdata::RData::TXT(simple_dns::rdata::TXT::from(txtrecord)),
                        ));
                    }
                    "SOA" => {
                        let mname = Name::new(msgparts.get(5).unwrap_or(&"")).unwrap();
                        let rname = Name::new(msgparts.get(6).unwrap_or(&"")).unwrap();
                        let serial = msgparts.get(7).unwrap_or(&"0").parse().unwrap_or(0);
                        let refresh = msgparts.get(8).unwrap_or(&"0").parse().unwrap_or(0);
                        let retry = msgparts.get(9).unwrap_or(&"0").parse().unwrap_or(0);
                        let expire = msgparts.get(10).unwrap_or(&"0").parse().unwrap_or(0);
                        let minimum = msgparts.get(11).unwrap_or(&"0").parse().unwrap_or(0);
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::SOA(simple_dns::rdata::SOA {
                                mname,
                                rname,
                                serial,
                                refresh,
                                retry,
                                expire,
                                minimum,
                            }),
                        ));
                    }
                    "SRV" => {
                        let priority = msgparts.get(5).unwrap_or(&"0").parse().unwrap_or(0);
                        let weight = msgparts.get(6).unwrap_or(&"0").parse().unwrap_or(0);
                        let port = msgparts.get(7).unwrap_or(&"0").parse().unwrap_or(0);
                        let target = Name::new(msgparts.get(8).unwrap_or(&"")).unwrap();
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::SRV(simple_dns::rdata::SRV {
                                priority,
                                weight,
                                port,
                                target,
                            }),
                        ));
                    }
                    "RP" => {
                        let mbox_dname = Name::new(msgparts.get(5).unwrap_or(&"")).unwrap();
                        let txt_dname = Name::new(msgparts.get(6).unwrap_or(&"")).unwrap();
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::RP(simple_dns::rdata::RP {
                                mbox: mbox_dname,
                                txt: txt_dname,
                            }),
                        ));
                    }
                    "AFSDB" => {
                        // AFSDB expects subtype and hostname
                        let subtype = msgparts.get(5).unwrap_or(&"0").parse().unwrap_or(0);
                        let hostname = Name::new(msgparts.get(6).unwrap_or(&"")).unwrap();
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::AFSDB(simple_dns::rdata::AFSDB {
                                subtype,
                                hostname,
                            }),
                        ));
                    }
                    // "NAPTR" => {
                    //     // NAPTR expects order, preference, flags, services, regexp, replacement
                    //     let order = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let preference = msgpart.get(19).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let flags = msgpart.get(20).unwrap_or(&"").as_bytes().to_vec();
                    //     let services = msgpart.get(21).unwrap_or(&"").as_bytes().to_vec();
                    //     let regexp = msgpart.get(22).unwrap_or(&"").as_bytes().to_vec();
                    //     let replacement = Name::new(msgpart.get(23).unwrap_or(&"")).unwrap();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         120,
                    //         simple_dns::rdata::RData::NAPTR(simple_dns::rdata::NAPTR {
                    //             order: order,
                    //             preference: preference,
                    //             flags: CharacterString::new(flags).unwrap(),
                    //             services: CharacterString::new(services).unwrap(),
                    //             regexp: CharacterString::new(msgpart.get(22).unwrap_or(&"").as_bytes()).unwrap(),
                    //             replacement: replacement,
                    //         }),
                    //     ));
                    // }
                    "LOC" => {
                        // LOC expects version, size, horiz_pre, vert_pre, latitude, longitude, altitude
                        let version = msgparts.get(5).unwrap_or(&"0").parse().unwrap_or(0);
                        let size = msgparts.get(6).unwrap_or(&"0").parse().unwrap_or(0);
                        let horiz_pre = msgparts.get(7).unwrap_or(&"0").parse().unwrap_or(0);
                        let vert_pre = msgparts.get(8).unwrap_or(&"0").parse().unwrap_or(0);
                        let latitude = msgparts.get(9).unwrap_or(&"0").parse().unwrap_or(0);
                        let longitude = msgparts.get(10).unwrap_or(&"0").parse().unwrap_or(0);
                        let altitude = msgparts.get(11).unwrap_or(&"0").parse().unwrap_or(0);
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::LOC(simple_dns::rdata::LOC {
                                version: version,
                                size: size,
                                vertical_precision: vert_pre,
                                horizontal_precision: horiz_pre,
                                altitude: altitude,
                                longitude: longitude,
                                latitude: latitude,
                            }),
                        ));
                    }
                    "OPT" => {
                        // SOA REPLY
                        let mname = Name::new(msgparts.get(5).unwrap_or(&"")).unwrap();
                        let rname = Name::new(msgparts.get(6).unwrap_or(&"")).unwrap();
                        let serial = msgparts.get(7).unwrap_or(&"0").parse().unwrap_or(0);
                        let refresh = msgparts.get(8).unwrap_or(&"0").parse().unwrap_or(0);
                        let retry = msgparts.get(9).unwrap_or(&"0").parse().unwrap_or(0);
                        let expire = msgparts.get(10).unwrap_or(&"0").parse().unwrap_or(0);
                        let minimum = msgparts.get(11).unwrap_or(&"0").parse().unwrap_or(0);
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::SOA(simple_dns::rdata::SOA {
                                mname,
                                rname,
                                serial,
                                refresh,
                                retry,
                                expire,
                                minimum,
                            }),
                        ));
                    }
                    "CAA" => {
                        let flags = msgparts.get(5).unwrap_or(&"0").parse().unwrap_or(0);
                        let tag_str = msgparts.get(6).unwrap_or(&"");
                        let tag_str = tag_str.trim_matches('"');
                        let value_str = msgparts.get(7).unwrap_or(&"");
                        let value_str = value_str.trim_matches('"');
                        let check = CharacterString::new(value_str.as_bytes());
                        let caa = simple_dns::rdata::CAA {
                            flag: flags,
                            tag: CharacterString::new(tag_str.as_bytes()).unwrap(),
                            value: std::borrow::Cow::from(value_str.as_bytes())
                        };

                        tracing::debug!("caa val: {:?}, {:?}, {:?}, {:?}", flags, tag_str, value_str, caa.value);
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::CAA(caa),
                        ));
                    }
                    "SVCB" => {
                        use std::collections::BTreeMap;
                        use std::borrow::Cow;

                        let priority = msgparts.get(5).unwrap_or(&"0").parse().unwrap_or(0);
                        let targetstr = msgparts.get(6).unwrap_or(&".").strip_suffix(".").unwrap_or("");
                        let target =  Name::new_unchecked(targetstr);
                        tracing::debug!("target: {:?} / {:?}", target, msgparts.get(6));
                        let mut svcb = SVCB::new(priority, target);
                        for param in msgparts[7..].iter() {
                            let parts: Vec<&str> = param.split('=').collect();
                            let parts: Vec<&str> = parts.iter().map(|s| s.trim_matches('"')).collect();
                            tracing::debug!("parts01: {:?}, {:?}", parts[0], parts[1]);
                            if parts.len() == 2 {
                                if parts[0] == "mandatory" {
                                    // Parse comma-separated list of u16
                                    let set = parts[1]
                                        .split(',')
                                        .filter_map(|s| s.parse::<u16>().ok())
                                        .collect::<BTreeSet<u16>>();
                                    svcb.set_mandatory(set.iter().copied());
                                } else if parts[0] == "alpn" {
                                    let alpn_vec: Vec<CharacterString> = parts[1]
                                        .split(',')
                                        .map(|s| CharacterString::new(s.as_bytes()).unwrap())
                                        .collect();
                                    svcb.set_alpn(&alpn_vec);
                                } else if parts[0] == "no-default-alpn" {
                                    svcb.set_no_default_alpn();
                                } else if parts[0] == "ipv4hint" {
                                    // Parse comma-separated list of IPv4 addresses as u32
                                    let hints: Vec<u32> = parts[1]
                                        .split(',')
                                        .filter_map(|s| s.parse::<Ipv4Addr>().ok())
                                        .map(|ip| u32::from(ip))
                                        .collect();
                                    svcb.set_ipv4hint(&hints);
                                } else if parts[0] == "port" {
                                    svcb.set_port(parts[1].parse().unwrap_or(0));
                                } else if parts[0] == "ech" {
                                    let ech = parts[1].as_bytes();
                                    svcb.set_param(simple_dns::rdata::SVCParam::Ech(std::borrow::Cow::from(ech)));
                                } else if parts[0] == "ipv6hint" {
                                    // Parse comma-separated list of IPv6 addresses as u128
                                    let hints: Vec<u128> = parts[1]
                                        .split(',')
                                        .filter_map(|s| s.parse::<Ipv6Addr>().ok())
                                        .map(|ip| u128::from(ip))
                                        .collect();
                                    svcb.set_ipv6hint(&hints);
                                } else {
                                    if let Ok(key) = parts[0].parse::<u16>() {
                                        svcb.set_param(simple_dns::rdata::SVCParam::Unknown(key, Cow::from(parts[1].as_bytes())));
                                    }
                                }
                            }
                        }
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::SVCB(svcb),
                        ));
                    }
                    "HTTPS" => {
                        use std::collections::BTreeMap;
                        use std::borrow::Cow;

                        let priority = msgparts.get(5).unwrap_or(&"0").parse().unwrap_or(0);
                        let targetstr = msgparts.get(6).unwrap_or(&".").strip_suffix(".").unwrap_or("");
                        let target =  Name::new_unchecked(targetstr);
                        tracing::debug!("target: {:?} / {:?}", target, msgparts.get(6));
                        let mut svcb = SVCB::new(priority, target);
                        for param in msgparts[7..].iter() {
                            let parts: Vec<&str> = param.split('=').collect();
                            let parts: Vec<&str> = parts.iter().map(|s| s.trim_matches('"')).collect();
                            tracing::debug!("parts01: {:?}, {:?}", parts[0], parts[1]);
                            if parts.len() == 2 {
                                if parts[0] == "mandatory" {
                                    // Parse comma-separated list of u16
                                    let set = parts[1]
                                        .split(',')
                                        .filter_map(|s| s.parse::<u16>().ok())
                                        .collect::<BTreeSet<u16>>();
                                    svcb.set_mandatory(set.iter().copied());
                                } else if parts[0] == "alpn" {
                                    let alpn_vec: Vec<CharacterString> = parts[1]
                                        .split(',')
                                        .map(|s| CharacterString::new(s.as_bytes()).unwrap())
                                        .collect();
                                    svcb.set_alpn(alpn_vec.as_slice());
                                } else if parts[0] == "no-default-alpn" {
                                    svcb.set_no_default_alpn();
                                } else if parts[0] == "ipv4hint" {
                                    // Parse comma-separated list of IPv4 addresses as u32
                                    let hints: Vec<u32> = parts[1]
                                        .split(',')
                                        .filter_map(|s| s.parse::<Ipv4Addr>().ok())
                                        .map(|ip| u32::from(ip))
                                        .collect();
                                    svcb.set_ipv4hint(&hints);
                                } else if parts[0] == "port" {
                                    svcb.set_port(parts[1].parse().unwrap_or(0));
                                } else if parts[0] == "ech" {
                                    let ech = parts[1].as_bytes();
                                    svcb.set_param(simple_dns::rdata::SVCParam::Ech(std::borrow::Cow::from(ech)));
                                } else if parts[0] == "ipv6hint" {
                                    // Parse comma-separated list of IPv6 addresses as u128
                                    let hints: Vec<u128> = parts[1]
                                        .split(',')
                                        .filter_map(|s| s.parse::<Ipv6Addr>().ok())
                                        .map(|ip| u128::from(ip))
                                        .collect();
                                    svcb.set_ipv6hint(&hints);
                                } else {
                                    if let Ok(key) = parts[0].parse::<u16>() {
                                        svcb.set_param(simple_dns::rdata::SVCParam::Unknown(key, Cow::from(parts[1].as_bytes())));
                                    }
                                }
                            }
                        }
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            msgparts[3].parse().unwrap_or(120),
                            simple_dns::rdata::RData::HTTPS(HTTPS::from(svcb))
                        ));
                    }
                    // "EUI48" => {
                    //     // EUI48 expects a 6-byte hex string
                    //     let eui48_hex = msgpart.get(17).unwrap_or(&"");
                    //     // let eui48 = hex::decode(eui48_hex).unwrap_or_default();
                    //     tracing::debug!("target: {:?} {:?}", eui48_hex, msgpart.get(18));
                    //     // let eui48 = EUI48::parse().unwrap();
                    //     // reply.answers.push(ResourceRecord::new(
                    //     //     question.qname.clone(),
                    //     //     simple_dns::CLASS::IN,
                    //     //     msgparts[3].parse().unwrap_or(120),
                    //     //     simple_dns::rdata::RData::EUI48(eui48),
                    //     // ));
                    // }
                    // "EUI64" => {
                    //     // EUI64 expects a 8-byte hex string
                    //     let eui64_hex = msgpart.get(17).unwrap_or(&"");
                    //     let eui64 = hex::decode(eui64_hex).unwrap_or_default();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::EUI64(eui64),
                    //     ));
                    // }
                    // "CERT" => {
                    //     // CERT expects type, key tag, algorithm, and certificate
                    //     let cert_type = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let key_tag = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let algorithm = msgpart.get(19).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let certificate = msgpart.get(20).map(|s| s.to_string()).unwrap_or_default();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::CERT(simple_dns::rdata::CERT {
                    //             cert_type,
                    //             key_tag,
                    //             algorithm,
                    //             certificate: std::borrow::Cow::from(certificate.as_bytes()),
                    //         }),
                    //     ));
                    // }
                    // "ZONEMD" => {
                    //     // ZONEMD expects a digest type and a digest
                    //     let digest_type = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let digest = msgpart.get(18).map(|s| s.to_string()).unwrap_or_default();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::ZONEMD(simple_dns::rdata::ZONEMD {
                    //             digest_type,
                    //             digest: std::borrow::Cow::from(digest.as_bytes()),
                    //         }),
                    //     ));
                    // }
                    // "KX" => {
                    //     // KX expects preference and target
                    //     let preference = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let target = Name::new(msgpart.get(18).unwrap_or(&"")).unwrap();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::KX(simple_dns::rdata::KX {
                    //             preference,
                    //             target,
                    //         }),
                    //     ));
                    // }
                    // "IPSECKEY" => {
                    //     // IPSECKEY expects precedence, gateway, algorithm, and public key
                    //     let precedence = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let gateway = msgpart.get(18).map(|s| s.to_string()).unwrap_or_default();
                    //     let algorithm = msgpart.get(19).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let public_key = msgpart.get(20).map(|s| s.to_string()).unwrap_or_default();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::IPSECKEY(simple_dns::rdata::IPSECKEY {
                    //             precedence,
                    //             gateway: std::borrow::Cow::from(gateway.as_bytes()),
                    //             algorithm,
                    //             public_key: std::borrow::Cow::from(public_key.as_bytes()),
                    //         }),
                    //     ));
                    // }
                    // "DNAME" => {
                    //     // DNAME expects a domain name
                    //     let dname = Name::new(msgparts[5]).unwrap();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::DNAME(simple_dns::rdata::DNAME::from(dname)),
                    //     ));
                    // }
                    // "RRSIG" => {
                    //     // RRSIG expects algorithm, labels, original_ttl, signature_expiration, signature_inception, key_tag, and signer_name
                    //     let algorithm = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let labels = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let original_ttl = msgpart.get(19).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let signature_expiration = msgpart.get(20).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let signature_inception = msgpart.get(21).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let key_tag = msgpart.get(22).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let signer_name = Name::new(msgpart.get(23).unwrap_or(&"")).unwrap();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::RRSIG(simple_dns::rdata::RRSIG {
                    //             algorithm,
                    //             labels,
                    //             original_ttl,
                    //             signature_expiration,
                    //             signature_inception,
                    //             key_tag,
                    //             signer_name,
                    //         }),
                    //     ));
                    // }
                    // "DS" => {
                    //     // DS expects key_tag, algorithm, digest_type, and digest
                    //     let key_tag = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let algorithm = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let digest_type = msgpart.get(19).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let digest = msgpart.get(20).map(|s| s.to_string()).unwrap_or_default();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::DS(simple_dns::rdata::DS {
                    //             key_tag,
                    //             algorithm,
                    //             digest_type,
                    //             digest: std::borrow::Cow::from(digest.as_bytes()),
                    //         }),
                    //     ));
                    // }
                    // "NSEC" => {
                    //     // NSEC expects next_domain_name and type_bit_maps
                    //     let next_domain_name = Name::new(msgparts[5]).unwrap();
                    //     let type_bit_maps = msgpart.get(18).map(|s| s.to_string()).unwrap_or_default();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::NSEC(simple_dns::rdata::NSEC {
                    //             next_domain_name,
                    //             type_bit_maps: std::borrow::Cow::from(type_bit_maps.as_bytes()),
                    //         }),
                    //     ));
                    // }
                    // "DHCID" => {
                    //     // DHCID expects a hex string
                    //     let dhcid_hex = msgpart.get(17).unwrap_or(&"");
                    //     let dhcid = hex::decode(dhcid_hex).unwrap_or_default();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::DHCID(dhcid),
                    //     ));
                    // }

                    //
                    // *** DQY NOT SUPPORTED ***
                    //

                    // "MD" => {
                    //     let madname = Name::new(msgparts[5]).unwrap();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::MD(simple_dns::rdata::MD::from(madname)),
                    //     ));
                    // }
                    // "MB" => {
                    //     let madname = Name::new(msgparts[5]).unwrap();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::MB(simple_dns::rdata::MB::from(madname)),
                    //     ));
                    // }
                    // "MG" => { ??????
                    //     let mgmname = Name::new(rststr.as_str()).unwrap();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         120,
                    //         simple_dns::rdata::RData::MG(simple_dns::rdata::MG::from(mgmname)),
                    //     ));
                    // }
                    // "MR" => { ???????
                    //     let newname = Name::new(rststr.as_str()).unwrap();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         120,
                    //         simple_dns::rdata::RData::MR(simple_dns::rdata::MR::from(newname)),
                    //     ));
                    // }
                    // "MF" => { ???????
                    //     let madname = Name::new(rststr.as_str()).unwrap();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         120,
                    //         simple_dns::rdata::RData::MF(simple_dns::rdata::MF::from(madname)),
                    //     ));
                    // }
                    // "MINFO" => {
                    //     // MININFO expects a domain name and a text string
                    //     let domain_name = Name::new(msgparts[5]).unwrap();
                    //     let text_string = msgpart.get(18).map(|s| s.to_string()).unwrap_or_default();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::MININFO(simple_dns::rdata::MININFO {
                    //             domain_name,
                    //             text_string: std::borrow::Cow::from(text_string.as_bytes()),
                    //         }),
                    //     ));
                    // }
                    // "WKS" => {
                    //     let address: Ipv4Addr = msgpart2.get(0).unwrap_or(&"0.0.0.0").parse().unwrap();
                    //     let protocol: u8 = msgpart2.get(1).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let bitmap_hex = msgpart2.get(2).unwrap_or(&"");
                    //     let bitmap = hex::decode(bitmap_hex).unwrap_or_default();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         120,
                    //         simple_dns::rdata::RData::WKS(simple_dns::rdata::WKS {
                    //             address: address.into(),
                    //             protocol: protocol,
                    //             bit_map: Cow::from(bitmap),
                    //         }),
                    //     ));
                    // }
                    // "ISDN" => {
                    //     // ISDN expects address and optional sa
                    //     let address = msgpart2.get(0).unwrap_or(&"").to_string();
                    //     let sa = msgpart2.get(1).map(|s| s.to_string());
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         120,
                    //         simple_dns::rdata::RData::ISDN(simple_dns::rdata::ISDN {
                    //             address: address.try_into().unwrap(),
                    //             sa: sa.try_into().unwrap(),
                    //         }),
                    //     ));
                    // }
                    // "NSAP" => {
                    //     // NSAP expects a hex string
                    //     let nsap_hex = msgpart.get(18).unwrap_or(&"");
                    //     let nsap = hex::decode(nsap_hex).unwrap_or_default();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         120,
                    //         simple_dns::rdata::RData::NSAP(nsap),
                    //     ));
                    // }
                    // "OPENPGPKEY" => {
                    //     // OpenPGPKEY expects a base64-encoded string
                    //     let key = msgpart.get(17).map(|s| s.to_string()).unwrap_or_default();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::OpenPGPKey(std::borrow::Cow::from(key.as_bytes())),
                    //     ));
                    // }
                    // "SSHFP" => {
                    //     // SSHFP expects algorithm, fingerprint_type, and fingerprint
                    //     let algorithm = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let fingerprint_type = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let fingerprint = msgpart.get(19).map(|s| s.to_string()).unwrap_or_default();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::SSHFP(simple_dns::rdata::SSHFP {
                    //             algorithm,
                    //             fingerprint_type,
                    //             fingerprint: std::borrow::Cow::from(fingerprint.as_bytes()),
                    //         }),
                    //     ));
                    // }
                    // "URI" => {
                    //     // URI expects priority, weight, target, and optional path
                    //     let priority = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let weight = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                    //     let target = msgpart.get(19).map(|s| s.to_string()).unwrap_or_default();
                    //     let path = msgpart.get(20).map(|s| s.to_string()).unwrap_or_default();
                    //     reply.answers.push(ResourceRecord::new(
                    //         question.qname.clone(),
                    //         simple_dns::CLASS::IN,
                    //         msgparts[3].parse().unwrap_or(120),
                    //         simple_dns::rdata::RData::URI(simple_dns::rdata::URI {
                    //             priority,
                    //             weight,
                    //             target: std::borrow::Cow::from(target.as_bytes()),
                    //         }),
                    //     ));
                    //     if !path.is_empty() {
                    //         reply.answers.last_mut().unwrap().rdata.set_path(std::borrow::Cow::from(path.as_bytes()));
                    //     }
                    // }
                    _ => {
                    }
                }
                index = index+1;
            }
        }
    }

    async fn get_messages_using_sync_transport<T: Messenger>(
        &self,
        info: QueryInfo,
        transport: &mut T,
        options: &CliOptions,
    ) -> dnslib::error::Result<MessageList> {
        // BUFFER_SIZE is the size of the buffer used to received data
        let messages = DnsProtocol::sync_process_request(options, transport, BUFFER_SIZE)?;
        tracing::debug!("received messages: {:?}", messages);
        Ok(messages)
    }

    async fn get_messages(&self, info: QueryInfo, options: &CliOptions) -> dnslib::error::Result<MessageList> {
        tracing::debug!("transport_mode : {:?}", options.transport.transport_mode);
        tracing::debug!("endpoint : {:?}", options.transport.endpoint);
        tracing::debug!("timeout : {:?}", options.transport.timeout);
        tracing::debug!("protocol : {:?}", options.protocol);
        tracing::debug!("service : {:?}", options.service);
        tracing::debug!("qtype : {:?}", options.protocol.qtype);
        tracing::debug!("domain_string : {:?}", options.protocol.domain_string);
        tracing::debug!("domain_name : {:?}", options.protocol.domain_name);
        tracing::debug!("fallback_addr : {:?}", options.service.fallback_addr);
        tracing::debug!("bind_addr : {:?}", options.service.bind_addr);
        
        match options.transport.transport_mode {
            Protocol::Udp => {
                let mut transport = UdpProtocol::new(&options.transport)?;
                self.get_messages_using_sync_transport(info, &mut transport, options).await
            }
            Protocol::Tcp => {
                let mut transport = TcpProtocol::new(&options.transport)?;
                self.get_messages_using_sync_transport(info, &mut transport, options).await
            }
            Protocol::DoT => {
                let mut transport = TlsProtocol::new(&options.transport)?;
                self.get_messages_using_sync_transport(info, &mut transport, options).await
            }
            Protocol::DoH => {
                let mut transport = HttpsProtocol::new(&options.transport)?;
                self.get_messages_using_sync_transport(info, &mut transport, options).await
            }
            Protocol::DoQ => {
                let mut transport = QuicProtocol::new(&options.transport).await?;
                let messages = DnsProtocol::async_process_request(options, &mut transport, BUFFER_SIZE).await?;
                Ok(messages)
            }
        }
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    // get arguments
    //───────────────────────────────────────────────────────────────────────────────────
    // skip program name
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut options = unsafe { crate::args::CliOptions::options(&args) }?;

    //───────────────────────────────────────────────────────────────────────────────────
    // this will give user some information on how the protocol ran
    //───────────────────────────────────────────────────────────────────────────────────
    let mut info = crate::show::QueryInfo::default();

    let endpoint = options.clone().transport.endpoint;
    tracing::info!("primary dns : {}",endpoint);
    for addr in &endpoint.addrs {
        // ignore ipv6 for now  
        if addr.ip().is_ipv6() {
            tracing::warn!("Ignoring IPv6 address: {}", addr.ip());
            continue;
        }
    }
    
    // parse and reply
    let handler: MyHandler = MyHandler { options: options.clone(), info };
    let bind_addr = options.service.bind_addr.clone().unwrap_or_else(|| "0.0.0.0:53".to_string());
    let fallback_addr = options.service.fallback_addr.clone().unwrap_or_else(|| "1.1.1.1:53".to_string());
    tracing::info!("fallback dns : {}",fallback_addr);
    tracing::info!("Listening on {}. Waiting for Ctrl-C...", bind_addr);
    let anydns: server::AnyDNS = Builder::new()
        .handler(handler)
        .icann_resolver(fallback_addr.parse().unwrap())
        .listen(bind_addr.parse().unwrap())
        .build()
        .await?;

    anydns.wait_on_ctrl_c().await;
    tracing::info!("Got it! Exiting...");
    anydns.stop();

    Ok(())
}
