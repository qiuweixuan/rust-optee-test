use std::u8;
use optee_utee::{BigInt,BigIntFMMContext,BigIntFMM};
use optee_utee::{
     trace_println
};
use optee_utee::{Result};
use optee_utee::{AlgorithmId, Digest,Mac};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use optee_utee::{Random};


struct DigestOp {
    op: Digest,
}


use  super::gp_bigint;
use  super::dragonfly_ffc;

use dragonfly_ffc::{FFCElement,Peer};






pub fn test_ffc_element_construct() -> Result<()> {

    static  DH_GROUP5_PRIME: [u8;192] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
        0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
        0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x23, 0x73, 0x27,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    ];
    static DH_GROUP5_ORDER: [u8;192] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xE4, 0x87, 0xED, 0x51, 0x10, 0xB4, 0x61, 0x1A,
        0x62, 0x63, 0x31, 0x45, 0xC0, 0x6E, 0x0E, 0x68,
        0x94, 0x81, 0x27, 0x04, 0x45, 0x33, 0xE6, 0x3A,
        0x01, 0x05, 0xDF, 0x53, 0x1D, 0x89, 0xCD, 0x91,
        0x28, 0xA5, 0x04, 0x3C, 0xC7, 0x1A, 0x02, 0x6E,
        0xF7, 0xCA, 0x8C, 0xD9, 0xE6, 0x9D, 0x21, 0x8D,
        0x98, 0x15, 0x85, 0x36, 0xF9, 0x2F, 0x8A, 0x1B,
        0xA7, 0xF0, 0x9A, 0xB6, 0xB6, 0xA8, 0xE1, 0x22,
        0xF2, 0x42, 0xDA, 0xBB, 0x31, 0x2F, 0x3F, 0x63,
        0x7A, 0x26, 0x21, 0x74, 0xD3, 0x1B, 0xF6, 0xB5,
        0x85, 0xFF, 0xAE, 0x5B, 0x7A, 0x03, 0x5B, 0xF6,
        0xF7, 0x1C, 0x35, 0xFD, 0xAD, 0x44, 0xCF, 0xD2,
        0xD7, 0x4F, 0x92, 0x08, 0xBE, 0x25, 0x8F, 0xF3,
        0x24, 0x94, 0x33, 0x28, 0xF6, 0x72, 0x2D, 0x9E,
        0xE1, 0x00, 0x3E, 0x5C, 0x50, 0xB1, 0xDF, 0x82,
        0xCC, 0x6D, 0x24, 0x1B, 0x0E, 0x2A, 0xE9, 0xCD,
        0x34, 0x8B, 0x1F, 0xD4, 0x7E, 0x92, 0x67, 0xAF,
        0xC1, 0xB2, 0xAE, 0x91, 0xEE, 0x51, 0xD6, 0xCB,
        0x0E, 0x31, 0x79, 0xAB, 0x10, 0x42, 0xA9, 0x5D,
        0xCF, 0x6A, 0x94, 0x83, 0xB8, 0x4B, 0x4B, 0x36,
        0xB3, 0x86, 0x1A, 0xA7, 0x25, 0x5E, 0x4C, 0x02,
        0x78, 0xBA, 0x36, 0x04, 0x65, 0x11, 0xB9, 0x93,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    ];


    // let prime = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
    // let order = b"7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267afc1b2ae91ee51d6cb0e3179ab1042a95dcf6a9483b84b4b36b3861aa7255e4c0278ba36046511b993ffffffffffffffff";
    // let group5_elemnt: FFCElement = FFCElement::new_from_hexstr(prime,order,true)?;
    // trace_println!("prime get_bit_count:{} , order get_bit_count {} .", group5_elemnt.prime.get_bit_count() + 64, 
    // group5_elemnt.order.get_bit_count() + 64);

    let group5_elemnt: FFCElement = FFCElement::new_from_gpstr(&DH_GROUP5_PRIME,&DH_GROUP5_ORDER,true)?;
    trace_println!("prime get_bit_count:{} , order get_bit_count {} .", group5_elemnt.prime.get_bit_count() + 64, 
    group5_elemnt.order.get_bit_count() + 64);

    let group5_elemnt: FFCElement = FFCElement::new()?;
    trace_println!("prime get_bit_count:{} , order get_bit_count {} .", group5_elemnt.prime.get_bit_count() + 64, 
    group5_elemnt.order.get_bit_count() + 64);

    let group5_elemnt: FFCElement = Default::default();
    trace_println!("prime get_bit_count:{} , order get_bit_count {} .", group5_elemnt.prime.get_bit_count() + 64, 
    group5_elemnt.order.get_bit_count() + 64);
    trace_println!("group5_elemnt:\n{}.", group5_elemnt);

    Ok(())
}





pub fn test_bigint() -> Result<()> {

    test_div_rem()?;
    test_div_rem_core()?;
    test_bigint_expmod()?;
    test_fmm()?;
    Ok(())
}


pub fn test_peer() -> Result<()> {

    test_compute_password_base()?;
    test_compute_password_key()?;
    test_password_element_derivation()?;
    test_peer_initiate()?;
    Ok(())
}




pub fn test_div_rem() -> Result<()> {

    let a0: BigInt = gp_bigint::bigint_construct_from_hexstr(b"a9fb57dba1eeb")?;
    let bn: u32 = 0xb57dba1e;
    let (q,r) = gp_bigint::div_rem_digit(&a0,bn);
    trace_println!("q:{},r:{:x}",q,r);

    let result = BigInt::multiply(&q,&q);
    trace_println!("result:{}",result);
    Ok(())
}

pub fn test_div_rem_core() -> Result<()> {


    let s1 = b"A9FB57DBA1EEB57DBA1EE";
    let s2 = b"B57DBA1EEABC1238";
    
    let a: BigInt = gp_bigint::bigint_construct_from_hexstr(s1)?;
    let b: BigInt = gp_bigint::bigint_construct_from_hexstr(s2)?;
    
    let (q,r) = gp_bigint::div_rem_core(&a,&b)?;
    trace_println!("q:{},r:{}",q,r);

    let prime = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
    let order = b"7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267afc1b2ae91ee51d6cb0e3179ab1042a95dcf6a9483b84b4b36b3861aa7255e4c0278ba36046511b993ffffffffffffffff";


    let a: BigInt = gp_bigint::bigint_construct_from_hexstr(prime)?;
    let b: BigInt = gp_bigint::bigint_construct_from_hexstr(order)?;
    let a = BigInt::multiply(&a,&a);

    let shift_bit = b.data.last().unwrap().leading_zeros() as usize;
    let shift_a = gp_bigint::bigint_shl(&a, shift_bit);
    let shift_b = gp_bigint::bigint_shl(&b, shift_bit);
    trace_println!("shift_a:{},\n shift_b:{}",shift_a,shift_b);
    let (q,r) = gp_bigint::div_rem_core(&shift_a,&shift_b)?;
    trace_println!("q:{},r:{}",q,r);

    Ok(())
}

pub fn test_fmm() -> Result<()> {
    let op1 = b"03e8";
    let op2 = b"0640";
    let op_mod = b"45";
    let op1 = gp_bigint::bigint_construct_from_hexstr(op1)?;
    let op2 = gp_bigint::bigint_construct_from_hexstr(op2)?;
    let op_mod = gp_bigint::bigint_construct_from_hexstr(op_mod)?;
    let result = BigInt::mul_mod(&op1,&op2,&op_mod);
    trace_println!("op1:{}",op1);
    trace_println!("op2:{}",op2);
    trace_println!("op_mod:{}",op_mod);
    trace_println!("mul_mod_result:{}",result);

    let op_mod_fmm_context = BigIntFMMContext::new(op_mod.get_bit_count(),&op_mod)?;
    

    let mut op1_fmm = BigIntFMM::new(op1.get_bit_count());
    op1_fmm.convert_from_big_int(&op1,&op_mod,&op_mod_fmm_context);

    let mut op2_fmm = BigIntFMM::new(op2.get_bit_count());
    op2_fmm.convert_from_big_int(&op2,&op_mod,&op_mod_fmm_context);

    let mut result_fmm = BigIntFMM::new(op_mod.get_bit_count());
    result_fmm.compute_fmm(&op1_fmm,&op2_fmm,&op_mod,&op_mod_fmm_context);

    let mut result_bigint = BigInt::new(op_mod.get_bit_count());
    result_bigint.convert_from_big_int_fmm(&result_fmm,&op_mod,&op_mod_fmm_context);
    trace_println!("fmm_result:{}",result_bigint);

    Ok(())
}



pub fn test_password_element_derivation() -> Result<()> {

    let group5_elemnt: FFCElement = Default::default(); 
    trace_println!("prime get_bit_count:{} , order get_bit_count {} .", group5_elemnt.prime.get_bit_count() + 64, 
    group5_elemnt.order.get_bit_count() + 64);
    trace_println!("group5_elemnt:\n{}.", group5_elemnt);
    let num_bits = group5_elemnt.prime.get_bit_count() + 64;


    let password: &[u8] = b"abc1238";
    let sta_mac: &[u8] = b"44:67:2D:2C:91:A6";
    let ap_mac: &[u8] = b"44:37:2C:2F:91:36";
    let sta_name:&[u8] = b"STA";
    let _ap_name:&[u8] = b"AP";
    let peer_sta = Peer::new(&password,&sta_mac,&sta_name,&group5_elemnt);

    let k: u8 = 40;
    let mut found = true;
    let label_str: &[u8] = b"Dragonfly Hunting And Pecking";
    let mut count: u8 = 1;


    let mut password_element = BigInt::new(0);
    while count <= k || found == false{
        
        let password_base = peer_sta.compute_hashed_password(&ap_mac, &count)?;
        //trace_println!("password_base:{:02x?}",password_base);

        let temp = peer_sta.compute_password_key(&password_base,label_str,num_bits)?;
        trace_println!("temp:{}",&temp);

        //seed = (temp mod(p - 1)) + 1
        let mut one = BigInt::new(1);
        one.convert_from_s32(1);
        let p_1 = BigInt::sub(&group5_elemnt.prime,&one);
        let seed = BigInt::module(&temp,&p_1);
        let mut seed = BigInt::add(&seed,&one);
        gp_bigint::bigint_normalize(&mut seed);
        trace_println!("seed:{}",&seed);

        // temp = seed ^ ((prime - 1) / order) mod prime

        let exp = match group5_elemnt.is_safe_prime {
            true =>{
                /*
                * exp = (prime - 1) / 2 for the group used here, so this becomes:
                * password_element (temp) = seed ^ 2 modulo prime
                */
                let mut two = BigInt::new(2);
                two.convert_from_s32(2);
                two
            },
            false =>{
                let (quot, _rem) = BigInt::divide(&p_1,&group5_elemnt.order);
                quot
            }
        };
        let seed = gp_bigint::bigint_expmod(&seed,&exp,&group5_elemnt.prime)?;
        trace_println!("seed:{}",&seed);
        
        if BigInt::compare_big_int(&seed,&one) > 0{
            password_element = seed;
            found = true;
        }
        
        count = count + 1;
    }
    trace_println!("password_element:{}",&password_element);


    Ok(())
}


pub fn test_peer_initiate() -> Result<()> {

    trace_println!("\n[+] TA invoke test_peer_initiate\n");

    let group5_elemnt: FFCElement = Default::default(); 

    let password: &[u8] = b"abc1238";
    let sta_mac: &[u8] = b"44:67:2D:2C:91:A6";
    let ap_mac: &[u8] = b"44:37:2C:2F:91:36";
    let sta_name:&[u8] = b"STA";
    let ap_name:&[u8] = b"AP";

    let peer_sta = Peer::new(&password,&sta_mac,&sta_name,&group5_elemnt);
    let sta_password_element = peer_sta.initiate(ap_mac)?;
    trace_println!("peer_sta.initiate password_element : {}",sta_password_element);
    
    let peer_ap = Peer::new(&password,&ap_mac,&ap_name,&group5_elemnt);
    let ap_password_element = peer_ap.initiate(sta_mac)?;
    trace_println!("peer_ap.initiate password_element : {}",ap_password_element);



    let (sta_private,sta_mask,sta_scalar,sta_element) = peer_sta.commit_exchange(&sta_password_element)?;
    let (ap_private,ap_mask,ap_scalar,ap_element) = peer_ap.commit_exchange(&ap_password_element)?;

    trace_println!("--------------------------");
    trace_println!("ap_scalar : {}",&ap_scalar);
    trace_println!("ap_element : {}",&ap_element);

    // let sta_password_element_str = b"643792bc5f7fad2ff7253a877e3eb99c63f4e4144540baeabd6343c9ef51fd66100317e1b46a5404c08a70b8672056b4afa724e59cea1d304ba3bdfed17e59ce5e38b2e0b7594180614f5503d3909ab31e33c7a423cdbf9f0b757186c6416bdcbdd67f321ae0534f042b871ff6cb5a3210644a1b680de6d8f1f47109ed9e98925e0ad6225940124913370e594497ba1453ae646f06abd21724197fb19a337d03e818b0f70152429c9879ffcae59a0f977c21f03647b2f303ace8d924b41f23be";
    // let sta_password_element = gp_bigint::bigint_construct_from_hexstr(sta_password_element_str)?;
    // let sta_private_str = b"2e5d3fea7d9d0d33ac553eecd5c3f27a310115d283e49377820195c8e67781b6f112a625b14b747fa4cc13d06eba0917246c775f5c732865701ae9349ea8729cde0bbade38204e63359a46e672a8d0a2fd5300692ab48f9ef732f5c3fa212b90c98229bbb79bece734a622154c904dce9a0f53d4a88b3e558ef7612f6694ce7518f204fe6846aeb6f58174d57a3372363c0d9fcfaa3dc18b1eff7e89bf7678636580d17dd84a873b14b9c0e1680bbdc87647f3c382902d2f58d2754b39bca874";
    // let sta_private = gp_bigint::bigint_construct_from_hexstr(sta_private_str)?;


    trace_println!("sta_password_element : {}",&sta_password_element);
    trace_println!("sta_private : {}",&sta_private);


    trace_println!("--------------------------");
    let (sta_kck,sta_ss_hex,sta_token) = peer_sta.compute_shared_secret(&ap_scalar,&ap_element,&sta_password_element,&sta_private,&sta_scalar,&sta_element)?;
    trace_println!("--------------------------");
    let (ap_kck,ap_ss_hex,ap_token) = peer_ap.compute_shared_secret(&sta_scalar,&sta_element,&ap_password_element,&ap_private,&ap_scalar,&ap_element)?;

      
    trace_println!("--------------------------");
    peer_sta.confirm_exchange(&ap_scalar,&ap_element,&sta_password_element,&sta_private,&sta_scalar,&sta_element,&sta_kck,&sta_ss_hex,&ap_token)?;
    trace_println!("--------------------------");
    peer_ap.confirm_exchange(&sta_scalar,&sta_element,&ap_password_element,&ap_private,&ap_scalar,&ap_element,&ap_kck,&ap_ss_hex,&sta_token)?;


    Ok(())
}





pub fn test_compute_password_base() -> Result<()> {

    let sha256_op = DigestOp{op:Digest::allocate(AlgorithmId::Sha256).unwrap()};

    let mac1: &[u8] = b"44:67:2D:2C:91:A6";
    let mac2: &[u8] = b"44:37:2C:2F:91:36";
    let min_mac = std::cmp::min(&mac1, &mac2);
    let max_mac = std::cmp::max(&mac1, &mac2);
    trace_println!("min_mac:{:?}", min_mac);
    trace_println!("max_mac:{:?}", max_mac);
    let mut mix_message: Vec<u8> = max_mac.to_vec();
    mix_message.extend(min_mac.into_iter());
    let password: &[u8] = b"abc1238";
    mix_message.extend(password.into_iter());
    mix_message.push(1);
    trace_println!("mix_message:{:02x?}", mix_message);
    

    let mut password_base: [u8; 32] = [0u8; 32];
    sha256_op.op.do_final(&mix_message,&mut password_base).unwrap();
    trace_println!("password_base:{:02x?}",password_base);

    Ok(())
}








pub fn hmac_sha256(key: &[u8], data: &[u8],out: &mut [u8]) -> Result<usize> {
    // const MAX_KEY_SIZE: usize = 64;
    // const MIN_KEY_SIZE: usize = 10;
    // if key.len() < MIN_KEY_SIZE || key.len() > MAX_KEY_SIZE {
    //     return Err(Error::new(ErrorKind::BadParameters));
    // }

    match Mac::allocate(AlgorithmId::HmacSha256, key.len() * 8) {
        Err(e) => return Err(e),
        Ok(mac) => {
            match TransientObject::allocate(TransientObjectType::HmacSha256, key.len() * 8) {
                Err(e) => return Err(e),
                Ok(mut key_object) => {
                    //KEY size can be larger than hotp.key_len
                    let mut tmp_key = key.to_vec();
                    tmp_key.truncate(key.len());
                    let attr = AttributeMemref::from_ref(AttributeId::SecretValue, &tmp_key);
                    key_object.populate(&[attr.into()])?;
                    mac.set_key(&key_object)?;
                }
            }
            mac.init(&[0u8; 0]);
            mac.update(&data);
            let out_len = mac.compute_final(&[0u8; 0], out).unwrap();
            Ok(out_len)
        }
    }
}


pub fn test_compute_password_key() -> Result<()> {

    let sha256_op = DigestOp{op:Digest::allocate(AlgorithmId::Sha256).unwrap()};

    let pwd_base_str: &[u8] = b"e64ff0945aef2ec8d6252acb8bce091f5e013e073c49607ed20bb1a35921c47d";
    let mut password_base = gp_bigint::gpstr_from_hexstr(pwd_base_str)?;

    
    trace_println!("password_base:{:02x?}",password_base);
    
    let label_str: &[u8] = b"Dragonfly Hunting And Pecking";
    password_base.extend(label_str.into_iter());
    trace_println!("password_base:{:02x?}",password_base);

    let mut kdf_hmac_key: [u8; 32] = [0u8; 32];
    sha256_op.op.do_final(&password_base,&mut kdf_hmac_key).unwrap();
    trace_println!("kdf_hmac_key:{:02x?}",kdf_hmac_key);

    let key_bits: usize = 320;
    let key_bytes: usize = (key_bits + 7) / 8;
    let mut rand_op: Vec<u8> = vec![0u8; key_bytes];
    Random::generate(&mut rand_op);
    trace_println!("rand_op:{:02x?},len:{}", rand_op,rand_op.len());


    //let message_bytes : &[u8] = b"1eff7e89bf7678636580d17dd84a873b14b9c0e1680bbdc87647f3c382902d2f";
    let message_bytes : &[u8] = b"1eff7e89bf7678636580d17dd84a873b14b9c0e1680bbdc87647f3c382902d2f58d2754b39bca874";
    let message = gp_bigint::gpstr_from_hexstr(message_bytes)?;
    
    
    let mut password_key_out = [0u8;32];
    hmac_sha256(&kdf_hmac_key,&message,&mut password_key_out)?;
    trace_println!("password_key_out:{:02x?}", password_key_out);

    let mac_len: usize = 32;
    let mut pos: usize = 0;
    let mut result_key: Vec<u8> = Vec::new();
    while pos < key_bytes{
        let mut message_len = mac_len;
        if key_bytes - pos < mac_len{
            message_len = key_bytes - pos;
        }
        let mut out_digest = [0u8;32];
        hmac_sha256(&kdf_hmac_key,&message[pos..pos+message_len],&mut out_digest)?;
        result_key.extend(&out_digest[0..message_len]);
        pos += message_len;
        trace_println!("out_digest:{:02x?}", &out_digest[0..message_len]);
    }
    trace_println!("result_key:{:02x?}",result_key);

    let mut bigint_result = BigInt::new(result_key.len() as u32 * 8);
    bigint_result.convert_from_octet_string(&result_key, 0)?;
    trace_println!("bigint_result:{}",bigint_result);


    Ok(())
}


pub fn test_bigint_expmod() -> Result<()> {
    let prime = b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
    let order = b"7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267afc1b2ae91ee51d6cb0e3179ab1042a95dcf6a9483b84b4b36b3861aa7255e4c0278ba36046511b993ffffffffffffffff";

    let op1 = &gp_bigint::bigint_construct_from_hexstr(prime)?;
    let op2 = &gp_bigint::bigint_construct_from_hexstr(order)?;
    let cal_result = &BigInt::multiply(op1,op1);
    let (_,cal_result) = &gp_bigint::bigint_div_rem(cal_result,op2)?;
    trace_println!("cal_result:{}",cal_result);
    Ok(())
}



