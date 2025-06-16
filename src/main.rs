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
use std::{error::Error, net::Ipv4Addr};
use std::borrow::Cow;
use std::net::Ipv6Addr;
use custom_handler::{CustomHandler, CustomHandlerError };
use server::{Builder};
use dns_socket::{DnsSocket};

use async_trait::async_trait;
use dnslib::dns::rfc::domain::DomainName;
use simple_dns::{CharacterString, Name, Packet, ResourceRecord, QTYPE, TYPE};
use simple_dns::rdata::{AAAA, A};
use simple_dns::rdata::RData::NS;
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
        // if question.qtype == QTYPE::TYPE(TYPE::CAA){ // unknown query type: caa
        //     self.options.protocol.qtype.push(QType::CAA)
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
        // if question.qtype == QTYPE::TYPE(TYPE::HTTPS){ // unknown query type: https
        //     self.options.protocol.qtype.push(QType::HTTPS)
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
        // if question.qtype == QTYPE::TYPE(TYPE::NAPTR){ // unknown query type: naptr
        //     self.options.protocol.qtype.push(QType::NAPTR);
        //     cantranslate = true;
        // }
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
        // if question.qtype == QTYPE::TYPE(TYPE::OPT){ // unknown query type: otp
        //     self.options.protocol.qtype.push(QType::OPT)
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
        // if question.qtype == QTYPE::TYPE(TYPE::SVCB){ // unknown query type: svcb
        //     self.options.protocol.qtype.push(QType::SVCB)
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

        if cantranslate {
            Ok(self.construct_reply_dqy(query).await) // Reply with A record IP
        } else {
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
        // tracing::info!("#### msg construct_reply_dqy ####");
        let messages = self.get_messages(self.info.clone(), &self.options).await;
        let messagestr = messages.unwrap();
        // tracing::info!("{}",messagestr);
        // ["\u{1b}[106;30mQUERY\u{1b}[0m", "\u{1b}[94mHEADER\u{1b}[0m(\u{1b}[96mid\u{1b}[0m:0xAD45(44357)", "\u{1b}[96mflags\u{1b}[0m:<rd", ">", "\u{1b}[96mqd_count\u{1b}[0m:1)", "\u{1b}[94mQUESTION\u{1b}[0m(\u{1b}[96mqname\u{1b}[0m:google.com.", "\u{1b}[96mqtype\u{1b}[0m:AAAA", "\u{1b}[96mqclass\u{1b}[0m:IN)", "\u{1b}[94mADDITIONAL\u{1b}[0m:(OPT(.", "OPT", "1232", "0", "0", "0))google.com.", "AAAA", "IN", "60", "16", "2404:6800:400a:805::200e", ".", "OPT", "1232", "0", "0", "0", "0"]

        let packet = Packet::parse(query).unwrap();
        let question = packet.questions.get(0).expect("Valid query");
        let mut reply = Packet::new_reply(packet.id());

        reply.questions.push(question.clone());
        if messagestr.len() == 0 {
            reply.build_bytes_vec().unwrap()
        }else{
            let rsvtext = messagestr.to_string();
            let msgpart: Vec<&str> =  rsvtext.split_whitespace().collect();
            // tracing::info!("{:?}",msgpart);
            // tracing::info!("{}",rsvtext);

            let rststr: String = msgpart[18].clone().to_string();
            let rststrmx: String = msgpart[19].clone().to_string();
            match msgpart[14] {
                "AAAA" => {
                    let rdata: Ipv6Addr = rststr.parse().unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        120,
                        simple_dns::rdata::RData::AAAA(rdata.try_into().unwrap()),
                    ));
                }
                "MX" => {
                    let preference: u16 = msgpart[18].parse().unwrap();
                    let exchange = Name::new(rststrmx.as_str()).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        120,
                        simple_dns::rdata::RData::MX(simple_dns::rdata::MX { preference, exchange }),
                    ));
                }
                "A" => {
                    let rdata: Ipv4Addr = rststr.parse().unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        120,
                        simple_dns::rdata::RData::A(rdata.try_into().unwrap()),
                    ));
                }
                "NS" => {
                    let nsdname = Name::new(rststr.as_str()).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        120,
                        simple_dns::rdata::RData::NS(simple_dns::rdata::NS::from(nsdname)),
                    ));
                }
                "CNAME" => {
                    let cname = Name::new(rststr.as_str()).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        120,
                        simple_dns::rdata::RData::CNAME(simple_dns::rdata::CNAME::from(cname)),
                    ));
                }
                "MB" => {
                    let madname = Name::new(rststr.as_str()).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        120,
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
                    let ptrdname = Name::new(rststr.as_str()).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        120,
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
                    let cpu = msgpart.get(18).unwrap_or(&"");
                    let os = msgpart.get(19).unwrap_or(&"");
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        120,
                        simple_dns::rdata::RData::HINFO(simple_dns::rdata::HINFO {
                            cpu: simple_dns::CharacterString::try_from(cpu.to_string()).unwrap(),
                            os: simple_dns::CharacterString::try_from(os.to_string()).unwrap(),
                        }),
                    ));
                }
                // "MINFO" => {
                //     let rmailbx = Name::new(msgpart.get(18).unwrap_or(&"")).unwrap();
                //     let emailbx = Name::new(msgpart.get(19).unwrap_or(&"")).unwrap();
                //     reply.answers.push(ResourceRecord::new(
                //         question.qname.clone(),
                //         simple_dns::CLASS::IN,
                //         120,
                //         simple_dns::rdata::RData::MINFO(simple_dns::rdata::MINFO {
                //             rmailbx,
                //             emailbx,
                //         }),
                //     ));
                // }
                "TXT" => {
                    let txt = msgpart.get(18).unwrap_or(&"");
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        120,
                        simple_dns::rdata::RData::TXT(simple_dns::rdata::TXT::new().with_string(txt).expect("REASON")),
                    ));
                }
                "SOA" => {
                    let mname = Name::new(msgpart.get(18).unwrap_or(&"")).unwrap();
                    let rname = Name::new(msgpart.get(19).unwrap_or(&"")).unwrap();
                    let serial = msgpart.get(20).unwrap_or(&"0").parse().unwrap_or(0);
                    let refresh = msgpart.get(21).unwrap_or(&"0").parse().unwrap_or(0);
                    let retry = msgpart.get(22).unwrap_or(&"0").parse().unwrap_or(0);
                    let expire = msgpart.get(23).unwrap_or(&"0").parse().unwrap_or(0);
                    let minimum = msgpart.get(24).unwrap_or(&"0").parse().unwrap_or(0);
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        120,
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
                //     let address: Ipv4Addr = msgpart.get(18).unwrap_or(&"0.0.0.0").parse().unwrap();
                //     let protocol: u8 = msgpart.get(19).unwrap_or(&"0").parse().unwrap_or(0);
                //     let bitmap_hex = msgpart.get(20).unwrap_or(&"");
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
                    let priority = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                    let weight = msgpart.get(19).unwrap_or(&"0").parse().unwrap_or(0);
                    let port = msgpart.get(20).unwrap_or(&"0").parse().unwrap_or(0);
                    let target = Name::new(msgpart.get(21).unwrap_or(&"")).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        120,
                        simple_dns::rdata::RData::SRV(simple_dns::rdata::SRV {
                            priority,
                            weight,
                            port,
                            target,
                        }),
                    ));
                }
                // "RP" => {
                //     let mbox_dname = Name::new(msgpart.get(18).unwrap_or(&"")).unwrap();
                //     let txt_dname = Name::new(msgpart.get(19).unwrap_or(&"")).unwrap();
                //     reply.answers.push(ResourceRecord::new(
                //         question.qname.clone(),
                //         simple_dns::CLASS::IN,
                //         120,
                //         simple_dns::rdata::RData::RP(simple_dns::rdata::RP {
                //             mbox_dname,
                //             txt_dname,
                //         }),
                //     ));
                // }
                "AFSDB" => {
                    // AFSDB expects subtype and hostname
                    let subtype = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                    let hostname = Name::new(msgpart.get(19).unwrap_or(&"")).unwrap();
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        120,
                        simple_dns::rdata::RData::AFSDB(simple_dns::rdata::AFSDB {
                            subtype,
                            hostname,
                        }),
                    ));
                }
                // "ISDN" => {
                //     // ISDN expects address and optional sa
                //     let address = msgpart.get(18).unwrap_or(&"").to_string();
                //     let sa = msgpart.get(19).map(|s| s.to_string());
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
                    let version = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                    let size = msgpart.get(19).unwrap_or(&"0").parse().unwrap_or(0);
                    let horiz_pre = msgpart.get(20).unwrap_or(&"0").parse().unwrap_or(0);
                    let vert_pre = msgpart.get(21).unwrap_or(&"0").parse().unwrap_or(0);
                    let latitude = msgpart.get(22).unwrap_or(&"0").parse().unwrap_or(0);
                    let longitude = msgpart.get(23).unwrap_or(&"0").parse().unwrap_or(0);
                    let altitude = msgpart.get(24).unwrap_or(&"0").parse().unwrap_or(0);
                    reply.answers.push(ResourceRecord::new(
                        question.qname.clone(),
                        simple_dns::CLASS::IN,
                        120,
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
                //     let udp_payload_size = msgpart.get(18).unwrap_or(&"4096").parse().unwrap_or(4096);
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
                //             udp_payload_size,
                //             extended_rcode,
                //             version,
                //             flags,
                //             data,
                //         }),
                //     ));
                // }
                // "CAA" => {
                //     // CAA expects flags, tag, value
                //     let flags = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                //     let tag = msgpart.get(19).unwrap_or(&"").to_string();
                //     let value = msgpart.get(20).unwrap_or(&"").to_string();
                //     reply.answers.push(ResourceRecord::new(
                //         question.qname.clone(),
                //         simple_dns::CLASS::IN,
                //         120,
                //         simple_dns::rdata::RData::CAA(simple_dns::rdata::CAA {
                //             flag: flags,
                //             tag: CharacterString::new(tag.as_ref()).unwrap(),
                //             value: CharacterString::new(value.as_ref()).unwrap(),
                //         }),
                //     ));
                // }
                // "SVCB" => {
                //     // SVCB expects priority, target, and params (as a hex string or base64, depending on your format)
                //     let priority = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                //     let target = Name::new(msgpart.get(19).unwrap_or(&"")).unwrap();
                //     // For params, you may need to parse a hex/base64 string or a custom format
                //     let params_hex = msgpart.get(20).unwrap_or(&"");
                //     let params = hex::decode(params_hex).unwrap_or_default();
                //     reply.answers.push(ResourceRecord::new(
                //         question.qname.clone(),
                //         simple_dns::CLASS::IN,
                //         120,
                //         simple_dns::rdata::RData::SVCB(simple_dns::rdata::SVCB {
                //             priority: priority,
                //             target: target,
                //             params: params
                //         }),
                //     ));
                // }
                // "HTTPS" => {
                //     // HTTPS expects priority, target, and params (as a hex string or base64, depending on your format)
                //     let priority = msgpart.get(18).unwrap_or(&"0").parse().unwrap_or(0);
                //     let target = Name::new(msgpart.get(19).unwrap_or(&"")).unwrap();
                //     // For params, you may need to parse a hex/base64 string or a custom format
                //     let params_hex = msgpart.get(20).unwrap_or(&"");
                //     let params = hex::decode(params_hex).unwrap_or_default();
                //     reply.answers.push(ResourceRecord::new(
                //         question.qname.clone(),
                //         simple_dns::CLASS::IN,
                //         120,
                //         simple_dns::rdata::RData::HTTPS(simple_dns::rdata::HTTPS {
                //             priority,
                //             target,
                //             params,
                //         }),
                //     ));
                // }
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

        Ok(messages)
    }

    async fn get_messages(&self, info: QueryInfo, options: &CliOptions) -> dnslib::error::Result<MessageList> {
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
    let mut dns_fallback = String::from("1.1.1.1");
    tracing::info!("primary dns : {}",endpoint);
    for addr in &endpoint.addrs {
        // ignore ipv6 for now  
        if addr.ip().is_ipv6() {
            tracing::warn!("Ignoring IPv6 address: {}", addr.ip());
            continue;
        }
        dns_fallback = addr.ip().to_string();
    }
    dns_fallback.push_str(":53");
    tracing::info!("fallback dns : {}",dns_fallback);
    // parse and reply
    let handler: MyHandler = MyHandler { options: options.clone(), info };
    let bind_addr = options.service.bind_addr.clone().unwrap_or_else(|| "0.0.0.0:53".to_string());
    tracing::info!("Listening on {}. Waiting for Ctrl-C...", bind_addr);
    let anydns: server::AnyDNS = Builder::new()
        .handler(handler)
        .icann_resolver(dns_fallback.parse().unwrap())
        .listen(bind_addr.parse().unwrap())
        .build()
        .await?;

    anydns.wait_on_ctrl_c().await;
    tracing::info!("Got it! Exiting...");
    anydns.stop();

    Ok(())
}
