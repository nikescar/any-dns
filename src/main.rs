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
use simple_dns::rdata::{AAAA, A, TXT, CNAME, HINFO, MX, PTR, SOA, SRV, HTTPS, AFSDB, LOC, SVCB };
use simple_dns::rdata::RData::NS;

use crate::args::CliOptions;
use crate::protocol::DnsProtocol;
use crate::show::QueryInfo;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum SVCParam<'a> {
    /// Mandatory keys in this RR. Key Code 0.
    Mandatory(BTreeSet<u16>),

    /// Additional supported protocols. Key Code 1.
    Alpn(Vec<CharacterString<'a>>),

    /// No support for default protocol. Key Code 2.
    NoDefaultAlpn,

    /// Port for alternative endpoint. Key Code 3.
    Port(u16),

    /// IPv4 address hints. Key Code 4.
    Ipv4Hint(Vec<u32>),

    /// Encrypted ClientHello (ECH) configuration. Key Code 5.
    Ech(Cow<'a, [u8]>),

    /// IPv6 address hints. Key Code 6.
    Ipv6Hint(Vec<u128>),

    /// Reserved for invalid keys. Key Code 65535.
    InvalidKey,

    /// Unknown key format.
    Unknown(u16, Cow<'a, [u8]>),
}


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
        // simple dns type does not exists
        if question.qtype == QTYPE::TYPE(TYPE::A){
            self.options.protocol.qtype.push(QType::A);
            cantranslate = true;
        }
        if question.qtype == QTYPE::TYPE(TYPE::AAAA){
            self.options.protocol.qtype.push(QType::AAAA);
            cantranslate = true;
        }
        if question.qtype == QTYPE::TYPE(TYPE::AFSDB){ // nslookup -type=afsdb google.com 8.8.8.8
            self.options.protocol.qtype.push(QType::AFSDB);
            cantranslate = true;
        }
        // if question.qtype == QTYPE::TYPE(TYPE::APL){
        //     self.options.protocol.qtype.push(QType::APL)
        // }
        if question.qtype == QTYPE::TYPE(TYPE::CAA){ // unknown query type: caa
            self.options.protocol.qtype.push(QType::CAA);
            cantranslate = true;
        }
        if question.qtype == QTYPE::TYPE(TYPE::SVCB){ // unknown query type: svcb
            self.options.protocol.qtype.push(QType::SVCB);
            cantranslate = true;
        }
        if question.qtype == QTYPE::TYPE(TYPE::HTTPS){ // unknown query type: https
            self.options.protocol.qtype.push(QType::HTTPS);
            cantranslate = true;
        }
        // if question.qtype == QTYPE::TYPE(TYPE::OPT){ // unknown query type: opt
        //     self.options.protocol.qtype.push(QType::OPT)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::CDNSKEY){
        //     self.options.protocol.qtype.push(QType::CDNSKEY)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::CDS){
        //     self.options.protocol.qtype.push(QType::CDS)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::CERT){
        //     self.options.protocol.qtype.push(QType::CERT)
        // }
        if question.qtype == QTYPE::TYPE(TYPE::CNAME){ // nslookup -query=cname google.com 8.8.8.8
            self.options.protocol.qtype.push(QType::CNAME);
            cantranslate = true;
        }
        // if question.qtype == QTYPE::TYPE(TYPE::CSYNC){
        //     self.options.protocol.qtype.push(QType::CSYNC)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::DHCID){
        //     self.options.protocol.qtype.push(QType::DHCID)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::DLV){
        //     self.options.protocol.qtype.push(QType::DLV)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::DNAME){
        //     self.options.protocol.qtype.push(QType::DNAME)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::DNSKEY){
        //     self.options.protocol.qtype.push(QType::DNSKEY)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::DS){
        //     self.options.protocol.qtype.push(QType::DS)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::EUI48){
        //     self.options.protocol.qtype.push(QType::EUI48)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::EUI64){
        //     self.options.protocol.qtype.push(QType::EUI64)
        // }
        if question.qtype == QTYPE::TYPE(TYPE::HINFO){ // nslookup -query=hinfo google.com 8.8.8.8
            self.options.protocol.qtype.push(QType::HINFO);
            cantranslate = true;
        }
        // if question.qtype == QTYPE::TYPE(TYPE::HIP){
        //     self.options.protocol.qtype.push(QType::HIP)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::IPSECKEY){
        //     self.options.protocol.qtype.push(QType::IPSECKEY)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::KX){
        //     self.options.protocol.qtype.push(QType::KX)
        // }
        if question.qtype == QTYPE::TYPE(TYPE::LOC){ // unknown query type: loc
            self.options.protocol.qtype.push(QType::LOC);
            cantranslate = true;
        }
        if question.qtype == QTYPE::TYPE(TYPE::MX){
            self.options.protocol.qtype.push(QType::MX);
            cantranslate = true;
        }
        if question.qtype == QTYPE::TYPE(TYPE::NAPTR){ // unknown query type: naptr
            self.options.protocol.qtype.push(QType::NAPTR);
            cantranslate = true;
        }
        if question.qtype == QTYPE::TYPE(TYPE::NS){ // nslookup -type=ns google.com 8.8.8.8
            self.options.protocol.qtype.push(QType::NS);
            cantranslate = true;
        }
        // if question.qtype == QTYPE::TYPE(TYPE::NSEC){
        //     self.options.protocol.qtype.push(QType::NSEC)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::NSEC3){
        //     self.options.protocol.qtype.push(QType::NSEC3)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::NSEC3PARAM){
        //     self.options.protocol.qtype.push(QType::NSEC3PARAM)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::OPENPGPKEY){
        //     self.options.protocol.qtype.push(QType::OPENPGPKEY)
        // }
        if question.qtype == QTYPE::TYPE(TYPE::PTR){ // nslookup -type=ptr google.com 8.8.8.8
            self.options.protocol.qtype.push(QType::PTR);
            cantranslate = true;
        }
        // if question.qtype == QTYPE::TYPE(TYPE::RP){ // nslookup -type=rp google.com 8.8.8.8
        //     self.options.protocol.qtype.push(QType::RP)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::RRSIG){
        //     self.options.protocol.qtype.push(QType::RRSIG)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::SMIMEA){
        //     self.options.protocol.qtype.push(QType::SMIMEA)
        // }
        if question.qtype == QTYPE::TYPE(TYPE::SOA){ // NOT SHOWING ANYTHING FROM DQY RESULT
            self.options.protocol.qtype.push(QType::SOA);
            cantranslate = true;
        }
        if question.qtype == QTYPE::TYPE(TYPE::SRV){ //nslookup -type=srv google.com 1.1.1.1
            self.options.protocol.qtype.push(QType::SRV);
            cantranslate = true;
        }
        // if question.qtype == QTYPE::TYPE(TYPE::SSHFP){
        //     self.options.protocol.qtype.push(QType::SSHFP)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::TLSA){
        //     self.options.protocol.qtype.push(QType::TLSA)
        // }
        if question.qtype == QTYPE::TYPE(TYPE::TXT){ //nslookup -type=txt google.com 127.0.0.1
            self.options.protocol.qtype.push(QType::TXT);
            cantranslate = true;
        }
        // if question.qtype == QTYPE::TYPE(TYPE::URI){
        //     self.options.protocol.qtype.push(QType::URI)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::ZONEMD){
        //     self.options.protocol.qtype.push(QType::ZONEMD)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::WALLET){
        //     self.options.protocol.qtype.push(QType::WALLET)
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
        tracing::debug!("{}",messagestr);
        let mut reply = Packet::new_reply(packet.id());
        //reply.answers.push(ResourceRecord::new(messages));
        reply.questions.push(question.clone());
        if messagestr.len() == 0 {
            reply.build_bytes_vec().unwrap()
        }else{
            let rsvtext = messagestr.to_string();
            let mut lines = rsvtext.lines();
            lines.next();
            let msgpart: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
            tracing::debug!("{:?}",msgpart);
            // tracing::debug!("{}",rsvtext);
            tracing::debug!("msgpart[13]: {}", msgpart[13]);
            match msgpart[13] {
                "AAAA" => {
                    let mut rststr: String = msgpart[17].clone().to_string();
                    let rdata: Ipv6Addr = rststr.parse().unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[16].parse().unwrap_or(120),
                        simple_dns::rdata::RData::AAAA(rdata.try_into().unwrap()),
                    ));
                }
                "MX" => {
                    let preference: u16 = msgpart[17].parse().unwrap();
                    let exchange = Name::new(msgpart[18]).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[15].parse().unwrap_or(120),
                        simple_dns::rdata::RData::MX(simple_dns::rdata::MX { preference, exchange }),
                    ));
                }
                "A" => {
                    let mut rststr: String = msgpart[17].clone().to_string();
                    let rdata: Ipv4Addr = rststr.parse().unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[16].parse().unwrap_or(120),
                        simple_dns::rdata::RData::A(rdata.try_into().unwrap()),
                    ));
                }
                "NS" => {
                    let nsdname = Name::new(msgpart[17]).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[15].parse().unwrap_or(120),
                        simple_dns::rdata::RData::NS(simple_dns::rdata::NS::from(nsdname)),
                    ));
                    loop {
                        let msgpart2: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
                        tracing::debug!("msgpart2: {}", msgpart2[0]);
                        let domain = Name::new(msgpart2[0]).unwrap();
                        let nstype = Name::new(msgpart2[1]).unwrap();
                        let eta = msgpart2[3].to_string();
                        if domain.to_string() == "." {
                            break;
                        }
                        if nstype.to_string() != "A" && nstype.to_string() != "AAAA"  {
                            continue;
                        }
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            eta.parse().unwrap_or(120),
                            simple_dns::rdata::RData::NS(simple_dns::rdata::NS::from(domain)),
                        ));
                    }
                }
                "CNAME" => {
                    let cname = Name::new(msgpart[17]).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[15].parse().unwrap_or(120),
                        simple_dns::rdata::RData::CNAME(simple_dns::rdata::CNAME::from(cname)),
                    ));
                }
                "MB" => {
                    let madname = Name::new(msgpart[17]).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[15].parse().unwrap_or(120),
                        simple_dns::rdata::RData::MB(simple_dns::rdata::MB::from(madname)),
                    ));
                }
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
                "PTR" => {
                    let ptrdname = Name::new(msgpart[17]).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[15].parse().unwrap_or(120),
                        simple_dns::rdata::RData::PTR(simple_dns::rdata::PTR::from(ptrdname)),
                    ));
                }
                // "MF" => { ???????
                //     let madname = Name::new(rststr.as_str()).unwrap();
                //     reply.answers.push(ResourceRecord::new(
                //         question.qname.clone(),
                //         simple_dns::CLASS::IN,
                //         120,
                //         simple_dns::rdata::RData::MF(simple_dns::rdata::MF::from(madname)),
                //     ));
                // }
                "HINFO" => {
                    let ptrdname = Name::new(msgpart[17]).unwrap();
                    let cpu = msgpart.get(18).unwrap_or(&"");
                    let os = msgpart.get(19).unwrap_or(&"");
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[15].parse().unwrap_or(120),
                        simple_dns::rdata::RData::HINFO(simple_dns::rdata::HINFO {
                            cpu: simple_dns::CharacterString::try_from(cpu.to_string()).unwrap(),
                            os: simple_dns::CharacterString::try_from(os.to_string()).unwrap(),
                        }),
                    ));
                }
                "TXT" => {
                    let nsdname = TXT::new().with_string(msgpart[17]).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[15].parse().unwrap_or(120),
                        simple_dns::rdata::RData::TXT(simple_dns::rdata::TXT::from(nsdname)),
                    ));
                    loop {
                        let msgpart2: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
                        let domain = Name::new(msgpart2[0]).unwrap();
                        let txtrecord = TXT::new().with_string(msgpart2[5]).unwrap();
                        let nstype = Name::new(msgpart2[1]).unwrap();
                        let eta = msgpart2[3].to_string();
                        if domain.to_string() == "." {
                            break;
                        }
                        reply.answers.push(ResourceRecord::new(
                            question.qname.clone(),
                            simple_dns::CLASS::IN,
                            eta.parse().unwrap_or(120),
                            simple_dns::rdata::RData::TXT(simple_dns::rdata::TXT::from(txtrecord)),
                        ));
                    }
                }
                "SOA" => {
                    let mname = Name::new(msgpart.get(17).unwrap_or(&"")).unwrap();
                    let rname = Name::new(msgpart.get(18).unwrap_or(&"")).unwrap();
                    let serial = msgpart.get(19).unwrap_or(&"0").parse().unwrap_or(0);
                    let refresh = msgpart.get(20).unwrap_or(&"0").parse().unwrap_or(0);
                    let retry = msgpart.get(21).unwrap_or(&"0").parse().unwrap_or(0);
                    let expire = msgpart.get(22).unwrap_or(&"0").parse().unwrap_or(0);
                    let minimum = msgpart.get(23).unwrap_or(&"0").parse().unwrap_or(0);
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[15].parse().unwrap_or(120),
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
                "SRV" => {
                    let priority = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                    let weight = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                    let port = msgpart.get(19).unwrap_or(&"0").parse().unwrap_or(0);
                    let target = Name::new(msgpart.get(20).unwrap_or(&"")).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[15].parse().unwrap_or(120),
                        simple_dns::rdata::RData::SRV(simple_dns::rdata::SRV {
                            priority,
                            weight,
                            port,
                            target,
                        }),
                    ));
                }
                // "RP" => {
                //     let mbox_dname = Name::new(msgpart.get(17).unwrap_or(&"")).unwrap();
                //     let txt_dname = Name::new(msgpart.get(18).unwrap_or(&"")).unwrap();
                //     reply.answers.push(ResourceRecord::new(
                //         question.qname.clone(),
                //         simple_dns::CLASS::IN,
                //         msgpart[15].parse().unwrap_or(120),
                //         simple_dns::rdata::RData::RP(simple_dns::rdata::RP {
                //             mbox_dname,
                //             txt_dname,
                //         }),
                //     ));
                // }
                "AFSDB" => {
                    // AFSDB expects subtype and hostname
                    let subtype = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                    let hostname = Name::new(msgpart.get(18).unwrap_or(&"")).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[15].parse().unwrap_or(120),
                        simple_dns::rdata::RData::AFSDB(simple_dns::rdata::AFSDB {
                            subtype,
                            hostname,
                        }),
                    ));
                }
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
                // "NAPTR" => {
                //     // NAPTR expects order, preference, flags, services, regexp, replacement
                //     let order = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                //     let preference = msgpart.get(19).unwrap_or(&"0").parse().unwrap_or(0);
                //     let flags = msgpart.get(20).unwrap_or(&"").to_string();
                //     let services = msgpart.get(21).unwrap_or(&"").to_string();
                //     let regexp = msgpart.get(22).unwrap_or(&"").to_string();
                //     let replacement = Name::new(msgpart.get(23).unwrap_or(&"")).unwrap();
                //     reply.answers.push(ResourceRecord::new(
                //         question.qname.clone(),
                //         simple_dns::CLASS::IN,
                //         120,
                //         simple_dns::rdata::RData::NAPTR(simple_dns::rdata::NAPTR {
                //             order: order,
                //             preference: preference,
                //             flags: CharacterString::new(flags.as_ref()).unwrap(),
                //             services: CharacterString::new(services.as_ref()).unwrap(),
                //             regexp: CharacterString::new(regexp.as_ref()).unwrap(),
                //             replacement: replacement,
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
                "LOC" => {
                    // LOC expects version, size, horiz_pre, vert_pre, latitude, longitude, altitude
                    let version = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                    let size = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                    let horiz_pre = msgpart.get(19).unwrap_or(&"0").parse().unwrap_or(0);
                    let vert_pre = msgpart.get(20).unwrap_or(&"0").parse().unwrap_or(0);
                    let latitude = msgpart.get(21).unwrap_or(&"0").parse().unwrap_or(0);
                    let longitude = msgpart.get(22).unwrap_or(&"0").parse().unwrap_or(0);
                    let altitude = msgpart.get(23).unwrap_or(&"0").parse().unwrap_or(0);
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[15].parse().unwrap_or(120),
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
                // "OPT" => {
                //     // OPT expects UDP payload size, extended RCODE, version, flags, and data
                //     let udp_packet_size = msgpart.get(18).unwrap_or(&"4096").parse().unwrap_or(4096);
                //     let extended_rcode = msgpart.get(19).unwrap_or(&"0").parse().unwrap_or(0);
                //     let version = msgpart.get(20).unwrap_or(&"0").parse().unwrap_or(0);
                //     let flags = msgpart.get(21).unwrap_or(&"0").parse().unwrap_or(0);
                //     let data_hex = msgpart.get(22).unwrap_or(&"");
                //     let data = hex::decode(data_hex).unwrap_or_default();
                //     reply.answers.push(ResourceRecord::new(
                //         question.qname.clone(),
                //         simple_dns::CLASS::IN,
                //         120,
                //         simple_dns::rdata::RData::OPT(simple_dns::rdata::OPT {
                //             udp_packet_size,
                //             version,
                //             opt_codes
                //         }),
                //     ));
                // }
                // "CAA" => {
                //     // CAA expects flags, tag, value
                //     let flags = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                //     let tag_str = msgpart.get(18).unwrap_or(&"");
                //     let value_str = msgpart.get(19).unwrap_or(&"");
                //     reply.answers.push(ResourceRecord::new(
                //         question.qname.clone(),
                //         simple_dns::CLASS::IN,
                //         msgpart[15].parse().unwrap_or(120),
                //         simple_dns::rdata::RData::CAA(simple_dns::rdata::CAA {
                //             flag: flags,
                //             tag: CharacterString::new(tag_str).unwrap(),
                //             value: CharacterString::new(value_str).unwrap(),
                //         }),
                //     ));
                // }
                // please add CAA types here
                "CAA" => {
                    let flags = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                    let tag_str = msgpart.get(18).unwrap_or(&"");
                    let tag_str = tag_str.trim_matches('"');
                    let value_str = msgpart.get(19).unwrap_or(&"");
                    let value_str = value_str.trim_matches('"');
                    let check = CharacterString::new(value_str.as_bytes());
                    let caa = simple_dns::rdata::CAA {
                            flag: flags,
                            tag: CharacterString::new(tag_str.as_bytes()).unwrap(),
                            value: CharacterString::new(value_str.as_bytes()).unwrap()
                        };

                    tracing::debug!("caa val: {:?}, {:?}, {:?}, {:?}", flags, tag_str, value_str, caa.value);
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[15].parse().unwrap_or(120),
                        simple_dns::rdata::RData::CAA(caa),
                    ));
                }
                "SVCB" => {
                    use std::collections::BTreeMap;
                    use std::borrow::Cow;

                    let priority = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                    let targetstr = msgpart.get(18).unwrap_or(&".").strip_suffix(".").unwrap_or("");
                    let target =  Name::new_unchecked(targetstr);
                    tracing::debug!("target: {:?} / {:?}", target, msgpart.get(18));
                    let mut svcb = SVCB::new(priority, target);
                    for param in msgpart[19..].iter() {
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
                                svcb.set_mandatory(set);
                            } else if parts[0] == "alpn" {
                                svcb.set_alpn(
                                    parts[1]
                                        .split(',')
                                        .map(|s| CharacterString::new(s.as_bytes()).unwrap())
                                        .collect::<Vec<CharacterString>>()
                                );
                            } else if parts[0] == "no-default-alpn" {
                                svcb.set_no_default_alpn();
                            } else if parts[0] == "ipv4hint" {
                                // Parse comma-separated list of IPv4 addresses as u32
                                let hints: Vec<u32> = parts[1]
                                    .split(',')
                                    .filter_map(|s| s.parse::<Ipv4Addr>().ok())
                                    .map(|ip| u32::from(ip))
                                    .collect();
                                svcb.set_ipv4hint(hints);
                            } else if parts[0] == "port" {
                                svcb.set_port(parts[1].parse().unwrap_or(0));
                            } else if parts[0] == "ech" {
                                let ech = parts[1].as_bytes();
                                svcb.set_param(5, std::borrow::Cow::from(ech));
                            } else if parts[0] == "ipv6hint" {
                                // Parse comma-separated list of IPv6 addresses as u128
                                let hints: Vec<u128> = parts[1]
                                    .split(',')
                                    .filter_map(|s| s.parse::<Ipv6Addr>().ok())
                                    .map(|ip| u128::from(ip))
                                    .collect();
                                svcb.set_ipv6hint(hints);
                            } else {
                                if let Ok(key) = parts[0].parse::<u16>() {
                                    svcb.set_param(key, Cow::from(parts[1].as_bytes()));
                                }
                            }
                        }
                    }
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[15].parse().unwrap_or(120),
                        simple_dns::rdata::RData::SVCB(svcb),
                    ));
                }
                "HTTPS" => {
                    use std::collections::BTreeMap;
                    use std::borrow::Cow;

                    let priority = msgpart.get(17).unwrap_or(&"0").parse().unwrap_or(0);
                    let targetstr = msgpart.get(18).unwrap_or(&".").strip_suffix(".").unwrap_or("");
                    let target =  Name::new_unchecked(targetstr);
                    tracing::debug!("target: {:?} / {:?}", target, msgpart.get(18));
                    let mut svcb = SVCB::new(priority, target);
                    for param in msgpart[19..].iter() {
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
                                svcb.set_mandatory(set);
                            } else if parts[0] == "alpn" {
                                svcb.set_alpn(
                                    parts[1]
                                        .split(',')
                                        .map(|s| CharacterString::new(s.as_bytes()).unwrap())
                                        .collect::<Vec<CharacterString>>()
                                );
                            } else if parts[0] == "no-default-alpn" {
                                svcb.set_no_default_alpn();
                            } else if parts[0] == "ipv4hint" {
                                // Parse comma-separated list of IPv4 addresses as u32
                                let hints: Vec<u32> = parts[1]
                                    .split(',')
                                    .filter_map(|s| s.parse::<Ipv4Addr>().ok())
                                    .map(|ip| u32::from(ip))
                                    .collect();
                                svcb.set_ipv4hint(hints);
                            } else if parts[0] == "port" {
                                svcb.set_port(parts[1].parse().unwrap_or(0));
                            } else if parts[0] == "ech" {
                                let ech = parts[1].as_bytes();
                                svcb.set_param(5, std::borrow::Cow::from(ech));
                            } else if parts[0] == "ipv6hint" {
                                // Parse comma-separated list of IPv6 addresses as u128
                                let hints: Vec<u128> = parts[1]
                                    .split(',')
                                    .filter_map(|s| s.parse::<Ipv6Addr>().ok())
                                    .map(|ip| u128::from(ip))
                                    .collect();
                                svcb.set_ipv6hint(hints);
                            } else {
                                if let Ok(key) = parts[0].parse::<u16>() {
                                    svcb.set_param(key, Cow::from(parts[1].as_bytes()));
                                }
                            }
                        }
                    }
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        msgpart[15].parse().unwrap_or(120),
                        simple_dns::rdata::RData::HTTPS(HTTPS::from(svcb))
                    ));
                }
                _ => {}
            }
            reply.build_bytes_vec().unwrap()
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
