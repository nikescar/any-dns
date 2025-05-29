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
use std::net::Ipv6Addr;
use custom_handler::{CustomHandler, CustomHandlerError };
use server::{Builder};
use dns_socket::{DnsSocket};

use async_trait::async_trait;
use dnslib::dns::rfc::domain::DomainName;
use simple_dns::{Name, Packet, ResourceRecord, QTYPE, TYPE};
use simple_dns::rdata::{AAAA, A};
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
        // if question.qtype == QTYPE::TYPE(TYPE::AFSDB){ // nslookup -type=afsdb google.com 8.8.8.8
        //     self.options.protocol.qtype.push(QType::AFSDB)
        // }
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
        // if question.qtype == QTYPE::TYPE(TYPE::CNAME){ // nslookup -query=cname google.com 8.8.8.8
        //     self.options.protocol.qtype.push(QType::CNAME)
        // }
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
        // if question.qtype == QTYPE::TYPE(TYPE::HINFO){ // nslookup -query=hinfo google.com 8.8.8.8
        //     self.options.protocol.qtype.push(QType::HINFO)
        // }
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
        // if question.qtype == QTYPE::TYPE(TYPE::LOC){ // unknown query type: loc
        //     self.options.protocol.qtype.push(QType::LOC)
        // }
        if question.qtype == QTYPE::TYPE(TYPE::MX){
            self.options.protocol.qtype.push(QType::MX);
            cantranslate = true;
        }
        // if question.qtype == QTYPE::TYPE(TYPE::NAPTR){ // unknown query type: naptr
        //     self.options.protocol.qtype.push(QType::NAPTR)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::NS){ // nslookup -type=ns google.com 8.8.8.8
        //     self.options.protocol.qtype.push(QType::NS)
        // }
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
        // if question.qtype == QTYPE::TYPE(TYPE::PTR){ // nslookup -type=ptr google.com 8.8.8.8
        //     self.options.protocol.qtype.push(QType::PTR)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::RP){ // nslookup -type=rp google.com 8.8.8.8
        //     self.options.protocol.qtype.push(QType::RP)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::RRSIG){
        //     self.options.protocol.qtype.push(QType::RRSIG)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::SMIMEA){
        //     self.options.protocol.qtype.push(QType::SMIMEA)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::SOA){ // NOT SHOWING ANYTHING FROM DQY RESULT
        //     self.options.protocol.qtype.push(QType::SOA)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::SRV){ //nslookup -type=srv google.com 1.1.1.1
        //     self.options.protocol.qtype.push(QType::SRV)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::SSHFP){
        //     self.options.protocol.qtype.push(QType::SSHFP)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::SVCB){ // unknown query type: svcb
        //     self.options.protocol.qtype.push(QType::SVCB)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::TLSA){
        //     self.options.protocol.qtype.push(QType::TLSA)
        // }
        // if question.qtype == QTYPE::TYPE(TYPE::TXT){ //nslookup -type=txt google.com 127.0.0.1
        //     self.options.protocol.qtype.push(QType::TXT)
        // }
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
            Ok(self.construct_reply_dqy(query)) // Reply with A record IP
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
    fn construct_reply_dqy(&self, query: &Vec<u8>) -> Vec<u8> {
        // tracing::info!("#### msg construct_reply_dqy ####");
        let messages = self.get_messages(self.info.clone(), &self.options);
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
            if msgpart[14] == "AAAA" {
                let rdata: Ipv6Addr = rststr.parse().unwrap();
                let record = ResourceRecord::new(
                    question.qname.clone(),
                    simple_dns::CLASS::IN,
                    120,
                    simple_dns::rdata::RData::AAAA(rdata.try_into().unwrap()),
                );
                reply.answers.push(record);
            }else if msgpart[14] == "MX" {
                let preference: u16 = msgpart[18].parse::<u16>().unwrap();;
                let exchange = Name::new(rststrmx.as_str()).unwrap();
                let mx_rdata = simple_dns::rdata::MX { preference, exchange };
                let record = ResourceRecord::new(
                    question.qname.clone(),
                    simple_dns::CLASS::IN,
                    120,
                    simple_dns::rdata::RData::MX(mx_rdata),
                );
                reply.answers.push(record);
            }else if msgpart[14] == "A"{
                let rdata: Ipv4Addr = rststr.parse().unwrap();
                let record = ResourceRecord::new(
                    question.qname.clone(),
                    simple_dns::CLASS::IN,
                    120,
                    simple_dns::rdata::RData::A(rdata.try_into().unwrap()),
                );
                reply.answers.push(record);
            }
            reply.build_bytes_vec().unwrap()
        }
    }

    fn get_messages_using_sync_transport<T: Messenger>(
        &self,
        info: QueryInfo,
        transport: &mut T,
        options: &CliOptions,
    ) -> dnslib::error::Result<MessageList> {
        // BUFFER_SIZE is the size of the buffer used to received data
        let messages = DnsProtocol::sync_process_request(options, transport, BUFFER_SIZE)?;

        // we want run info
        // if let Some(info) = info {
        //     info.netinfo = *transport.network_info();
        // }

        Ok(messages)
    }

    fn get_messages(&self, info: QueryInfo, options: &CliOptions) -> dnslib::error::Result<MessageList> {
        match options.transport.transport_mode {
            Protocol::Udp => {
                let mut transport = UdpProtocol::new(&options.transport)?;
                self.get_messages_using_sync_transport(info, &mut transport, options)
            }
            Protocol::Tcp => {
                let mut transport = TcpProtocol::new(&options.transport)?;
                self.get_messages_using_sync_transport(info, &mut transport, options)
            }
            Protocol::DoT => {
                let mut transport = TlsProtocol::new(&options.transport)?;
                self.get_messages_using_sync_transport(info, &mut transport, options)
            }
            Protocol::DoH => {
                let mut transport = HttpsProtocol::new(&options.transport)?;
                self.get_messages_using_sync_transport(info, &mut transport, options)
            }
            Protocol::DoQ => {
                // quinn crate doesn't provide blocking
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(Tokio)?;
    
                rt.block_on(async {
                    let mut transport = QuicProtocol::new(&options.transport).await?;
                    let messages = DnsProtocol::async_process_request(options, &mut transport, BUFFER_SIZE).await?;
    
                    // we want run info
                    // if let Some(info) = info {
                    //     info.netinfo = *transport.network_info();
                    // }
                    Ok(messages)
                })
            }
            
        }
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("Listening on 0.0.0.0:53. Waiting for Ctrl-C...");

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
        // try to connect
        // println!("addr: {} ", addr);
        dns_fallback = addr.ip().to_string();
    }
    dns_fallback.push_str(":53");
    tracing::info!("fallback dns : {}",dns_fallback);
    // parse and reply
    let handler: MyHandler = MyHandler { options, info };
    let anydns: server::AnyDNS = Builder::new()
        .handler(handler)
        .icann_resolver(dns_fallback.parse().unwrap())
        .build()
        .await?;

    anydns.wait_on_ctrl_c().await;
    tracing::info!("Got it! Exiting...");
    anydns.stop();

    Ok(())
}
