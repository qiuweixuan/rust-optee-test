use std::{u8, fmt};

use optee_utee::BigInt;

use optee_utee::{
     trace_println
};

use optee_utee::{Result};
use optee_utee::{AlgorithmId, Digest,Mac};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use optee_utee::{Random};

use  super::gp_bigint;

struct DigestOp {
    op: Digest,
}

use std::cmp;



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
/* 
static  DH_GROUP1_PRIME: [u8;96] = [
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
	0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x3A, 0x36, 0x20,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
];
static DH_GROUP1_ORDER: [u8;96] = [
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
	0x7A, 0x26, 0x21, 0x74, 0xD3, 0x1D, 0x1B, 0x10,
	0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
];
 */
pub struct FFCElement<'a>{
    pub prime: BigInt,
    pub order: BigInt,
    pub is_safe_prime:bool,
    pub prime_gp_array: &'a [u8],
    pub order_gp_array: &'a [u8],
}   


//构造函数
impl<'a> FFCElement<'a>{
    pub fn new() -> Result< Self >{
        let instance: FFCElement = FFCElement::new_from_gpstr(&DH_GROUP5_PRIME,&DH_GROUP5_ORDER,true)?;
        Ok(instance)
    }
    /* 
    pub fn new_from_hexstr(prime_hex_array: &[u8],order_hex_array: &[u8],is_safe_prime:bool) -> Result< Self >{
        let prime_u8_array = gp_bigint::gpstr_from_hexstr(prime_hex_array)?;
        let order_u8_array = gp_bigint::gpstr_from_hexstr(order_hex_array)?;
        
        // let prime = gp_bigint::bigint_construct_from_hexstr(prime)?;
        // let order = gp_bigint::bigint_construct_from_hexstr(order)?;
        let instance: FFCElement = FFCElement::new_from_gpstr(&prime_u8_array,&order_u8_array,is_safe_prime)?;
        Ok(instance)
    }
     */
    pub fn new_from_gpstr(prime_gp_array: &'a[u8],order_gp_array: &'a[u8],is_safe_prime:bool) -> Result< Self >{
        let prime = gp_bigint::bigint_construct_from_gpstr(prime_gp_array)?;
        let order = gp_bigint::bigint_construct_from_gpstr(order_gp_array)?;
        Ok(Self{prime,order,is_safe_prime,prime_gp_array,order_gp_array})
    }

    pub fn scalar_op(self: &Self,op_exp: &BigInt, op_base: &BigInt) -> Result<BigInt>{
        
        
        let rop = gp_bigint::bigint_expmod(&op_base, &op_exp, &self.prime)?;
        Ok(rop)
    }

    pub fn element_op(self: &Self,op1: &BigInt,op2: &BigInt) -> Result<BigInt>{
        // let mul = BigInt::multiply(&op1,&op2);
        // let (_,rop) = gp_bigint::bigint_div_rem(&mul,&self.prime)?;
        let rop = BigInt::mul_mod(&op1,&op2,&self.prime);
        Ok(rop)
    }

    pub fn inverse_op(self: &Self,op: &BigInt) -> Result<BigInt>{
        let rop = BigInt::inv_mod(&op,&self.prime);
        Ok(rop)
    }
}

//显示函数
impl fmt::Display for FFCElement<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "prime : {} \n order : {}", self.prime,self.order)
    }
}

impl Default for FFCElement<'static> {
    fn default() -> FFCElement<'static> { 
        match FFCElement::new(){
            Ok(instance) => instance,
            Err(_) => {panic!("FFCElement default error");}
        }
    }
}


pub struct Peer<'a>{
    pub local_password: &'a [u8],
    pub local_mac: &'a [u8],
    pub local_name:  &'a [u8],
    pub ffc_elemnt: &'a FFCElement<'a>,
}

impl<'a> Peer<'a>{
    pub fn new(local_password: &'a [u8],local_mac: &'a [u8], local_name: &'a [u8],ffc_elemnt: &'a FFCElement) -> Self {
        Self{
            local_password,
            local_mac,
            local_name,
            ffc_elemnt
        }
    }

    pub fn compute_hashed_password(self: &Self, peer_mac: &[u8],count : &u8) -> Result<([u8; 32])> {

        let sha256_op = DigestOp{op:Digest::allocate(AlgorithmId::Sha256).unwrap()};

        let min_mac = std::cmp::min(&self.local_mac, &peer_mac);
        let max_mac = std::cmp::max(&self.local_mac, &peer_mac);
    
        let mut hashed_password: [u8; 32] = [0u8; 32];
        sha256_op.op.update(max_mac);
        sha256_op.op.update(min_mac);
        sha256_op.op.update(self.local_password);
        sha256_op.op.do_final(&[*count;1],&mut hashed_password).unwrap();

        Ok(hashed_password)
    }


    pub fn compute_password_key(self: &Self,password_base: &[u8],label_str: &[u8],key_bits: u32) -> Result<(BigInt)> {

        let sha256_op = DigestOp{op:Digest::allocate(AlgorithmId::Sha256).unwrap()};
        let  kdf_key: &mut [u8; 32] = &mut [0u8; 32];
        sha256_op.op.update(password_base);
        sha256_op.op.do_final(label_str,kdf_key).unwrap();
        // trace_println!("kdf_key:{:02x?}",kdf_key);

        let result_key = Self::sha256_prf_bits(kdf_key,label_str,self.ffc_elemnt.prime_gp_array,key_bits)?;
        // trace_println!("len:{},result_key:{:02x?}",result_key.len(),result_key);
        
        let bigint_result = gp_bigint::bigint_construct_from_gpstr(&result_key)?;

        // trace_println!("bigint_result:{}",bigint_result);
        Ok(bigint_result)
    }

    pub fn sha256_prf_bits(key: &[u8],label_str: &[u8], data: &[u8], buf_len_bits : u32) -> Result<Vec<u8>> {
        // use std::mem;

        let buf_len: usize = (buf_len_bits as usize + 7) / 8;
        let mut message = Vec::new();
        /* 
        unsafe{
            let bits_u8_array = mem::transmute::<u32,[u8; 4]>(buf_len_bits);
            message.extend(&bits_u8_array);
        }
         */
        let bits_u8_array = gp_bigint::transmute_u32_to_u8array(buf_len_bits,gp_bigint::U32Kind::LE);
        message.extend(&bits_u8_array);
        message.extend(label_str);
        message.extend(data);
        // trace_println!("message:{:x?}",message);
        

        let message_pre_len = message.len();
        
        let mac_len: usize = 32;
        let mut pos: usize = 0;
        let mut count:u32 = 0;
        let mut result_buf: Vec<u8> = Vec::new();
        while pos < buf_len{
            let mut message_len = mac_len;
            if buf_len - pos < mac_len{
                message_len = buf_len - pos;
            }

            let mut out_digest = [0u8;32];
            message.truncate(message_pre_len);
            /* 
            unsafe{
                let count_u8_array = mem::transmute::<u32,[u8; 4]>(count);
                message.extend(&count_u8_array);
            }
             */
            let count_u8_array = gp_bigint::transmute_u32_to_u8array(count,gp_bigint::U32Kind::LE);
            message.extend(&count_u8_array);
            // trace_println!("count_u8_array:{:x?}",&count_u8_array);

            Self::hmac_sha256(&key,&message,&mut out_digest)?;
            result_buf.extend(&out_digest[0..message_len]);
        
            pos += message_len;
            count += 1;
        }

        Ok(result_buf)
    }


    pub fn initiate(self: &Self,peer_mac: &[u8]) -> Result<BigInt> {

        
        let num_bits = self.ffc_elemnt.prime.get_bit_count() + 64;

        let  k: u8 = 40;
        let mut found = true;
        let label_str: &[u8] = b"Dragonfly Hunting And Pecking";
        let mut count: u8 = 1;


        let mut password_element = BigInt::new(0);
        while count <= k || found == false{
            
            let password_base = self.compute_hashed_password(&peer_mac, &count)?;
            // trace_println!("password_base:{:02x?}",password_base);

            let temp = self.compute_password_key(&password_base,label_str,num_bits)?;
            // trace_println!("temp:{}",&temp);

            //seed = (temp mod(p - 1)) + 1
            let mut one = BigInt::new(1);
            one.convert_from_s32(1);
            let p_1 = BigInt::sub(&self.ffc_elemnt.prime,&one);
            let seed = BigInt::module(&temp,&p_1);
            let mut seed = BigInt::add(&seed,&one);
            gp_bigint::bigint_normalize(&mut seed);
            // trace_println!("seed:{}",&seed);

            // temp = seed ^ ((prime - 1) / order) mod prime

            let exp = match self.ffc_elemnt.is_safe_prime {
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
                    let (quot, _rem) = BigInt::divide(&p_1,&self.ffc_elemnt.order);
                    quot
                }
            };
            let seed = gp_bigint::bigint_expmod(&seed,&exp,&self.ffc_elemnt.prime)?;
            // trace_println!("seed:{}",&seed);
            
            if BigInt::compare_big_int(&seed,&one) > 0{
                password_element = seed;
                found = true;
            }
            
            count = count + 1;
        }
        // trace_println!("password_element:{}",&password_element);


        Ok(password_element)
    }

    pub fn commit_exchange(self: &Self,password_element: &BigInt) -> Result<(BigInt,BigInt,BigInt,BigInt)> {
        let rand_bits: usize = self.ffc_elemnt.order.get_bit_count() as usize;
        let rand_bytes: usize = (rand_bits + 7) / 8;
        let two = gp_bigint::bigint_construct_from_s32(2);

        let mut rand_op: Vec<u8> = vec![0u8; rand_bytes];

        Random::generate(&mut rand_op);
        let rand_bigint = gp_bigint::bigint_construct_from_gpstr(&rand_op)?;
        let  (_, mut private) = gp_bigint::bigint_div_rem(&rand_bigint, &self.ffc_elemnt.order)?;
        if BigInt::compare_big_int(&private,&two) < 0{
            private = gp_bigint::bigint_assign(&two);
        }

        Random::generate(&mut rand_op);
        let rand_bigint = gp_bigint::bigint_construct_from_gpstr(&rand_op)?;
        let (_, mut mask) = gp_bigint::bigint_div_rem(&rand_bigint, &self.ffc_elemnt.order)?;
        if BigInt::compare_big_int(&mask,&two) < 0{
            mask = gp_bigint::bigint_assign(&two);
        }

        trace_println!("private:{}",&private);
        trace_println!("mask:{}",&mask);

        // let private_str = b"8e57582f9852ad12cf0ee16f2440678d35a31147278a27658a66182b41c8327a559d058a9e9df5a55fe9eeccd16fd651c2d7f13a9942e7418052b4ae1b98f8ca3f3e828532a453289bd47b363738f866debf04222abeecac1e11f980b6f115f097f4540aa7735b993f17f55083caeb6a80f80d092c59d2f895f783fab56a353b58a8c4316eacf3012c77e6fbfdb4be7ed3cd27fc1c72a98f7733050ae2a4bd8c2b356f3f81de6f56258f69355b9321117b905723db3fe533ff94c12502b145c";
        // let private = gp_bigint::bigint_construct_from_hexstr(private_str)?;

        // let mask_str = b"7cc716330a37576e5021ca2fd2f24b31e027c0b9bc2929f2a2a38c9d003ae5b45d153957d2d0fe1cd05a87f375d050f6341d1e83f0583276902503259190aa7b0353e99a8b404da6feabe3a3b4a54263523a3619aedffe301db8be0aa07b04b8d8c1210cbb3034856d6f46dec94cf866558439083e26bd03dc4c11a81239654b516b2f891d20d0f7fc98547fac560ab315de74e6eb71dccef15a3ac85d3daa6072603a608a1d9201d5f09ad67ed8ce94a6b25eb8a8fc7c1f2a46626cf17c40bc";
        // let mask = gp_bigint::bigint_construct_from_hexstr(mask_str)?;


        // scalar = (private + mask) modulo q
        let scalar = BigInt::add(&private,&mask);
        let (_, scalar) = gp_bigint::bigint_div_rem(&scalar, &self.ffc_elemnt.order)?;

        //Element = inverse(scalar-op(mask, PE))
        let element = self.ffc_elemnt.scalar_op(&mask,&password_element)?;
        let element = self.ffc_elemnt.inverse_op(&element)?;

        
        trace_println!("scalar:{}",&scalar);
        trace_println!("element:{}",&element);


        Ok((private,mask,scalar,element))
    }


    pub fn compute_shared_secret(self: &Self,peer_scalar: &BigInt, peer_element: &BigInt,password_element: &BigInt,private: &BigInt,scalar: &BigInt,element: &BigInt) -> Result<(Vec<u8>,Vec<u8>,Vec<u8>)> {
        
        // ss = scalar-op(peer-commit-scalar, PWE)
        let  ss = self.ffc_elemnt.scalar_op(&peer_scalar, &password_element)?;
        trace_println!("ss:\n{}",&ss);

        // ss = elem-op(ss,PEER-COMMIT-ELEMENT)
        let ss = self.ffc_elemnt.element_op(&ss, &peer_element)?;
        trace_println!("ss:\n{}",&ss);


        // ss = scalar-op(private, ss)
        let ss = self.ffc_elemnt.scalar_op(&private, &ss)?;
        trace_println!("ss:\n{}",&ss);

       /* keyseed = H(<0>32, k)
        * KCK || PMK = KDF-512(keyseed, "SAE KCK and PMK",
        *                      (commit-scalar + peer-commit-scalar) modulo r)
        * PMKID = L((commit-scalar + peer-commit-scalar) modulo r, 0, 128)
        */
        
        // let peer_scalar_str = b"24355f300e3421ea95bb2617ea14b58a5b91223e034dfd8ce1fb6d94f1e4f9edfe98959a0ee39b6ec2b0c92fd6cc0c57bc4e031066b1687f8fe227e601434fdd62d1773aeb8c55f438e3e5ef76276caf102a96207faf65fbcc5c1ac7e9653da632c77fd33fa4ecbcce55ea0764dd1c84116ec1a844c19da3791d116b6e0132317ec535c9171ac3223dc732bbf17da3217bc73bc20500c729f6c13097979f478b101f8640a371cfee6d1efd5ccc5de54e3a72713348d2ba1de6666229dd1b2e2";
        // let peer_scalar = gp_bigint::bigint_construct_from_hexstr(peer_scalar_str)?;

        // let peer_element_str = b"57a729afd4999563a638e32f64a0c8c8185f0280db86aae466e00e81c81f92a6f1a03ea1a7d8ad4df03c17018292aa6aaf31398fcc5703b56d8123dcb6a1cc8e1b928d727a7a20458f0acca3968f571f0edf9732b9f1e93f035e93b6873e140b9ed410e1f761632b284e899b4e01e4280383ad9233bb82084a16cbeba69c3f25823de89c9e26ef007614af2133712f735880e00d26f331fb0656ff23accb82aa7fd55f15f1c9866dc4a5a11586b09a9e72921f5ebe7c32d4eeea69a4ba4fc8e";
        // let peer_element = gp_bigint::bigint_construct_from_hexstr(peer_element_str)?;

        let scalar_result = BigInt::add_mod(&scalar,&peer_scalar,&self.ffc_elemnt.order);
        trace_println!("scalar:\n {}", &scalar);
        trace_println!("peer_scalar:\n {}", &peer_scalar);
        trace_println!("scalar_result:\n {}", &scalar_result);

        //trace_println!("scalar_result:\n {:x?}", gp_bigint::bigint_to_hexstr(&scalar_result));

        let nullkey: &[u8] = &[0u8;32];
        let ss_hex = ss.convert_to_octet_string()?;
        trace_println!("ss_hex:\n {:02x?}", &ss_hex);

        let mut keyseed = [0u8;32];
        Self::hmac_sha256(&nullkey,&ss_hex,&mut keyseed)?;
        trace_println!("ss_hex:\n {:02x?}", &keyseed);

        let label_str: &[u8] = b"SAE KCK and PMK";
        //let data = gp_bigint::bigint_to_hexstr(&scalar_result)?;
        let data = scalar_result.convert_to_octet_string()?;
        trace_println!("data:\n {:02x?}", &data);

        let key_buf = Self::sha256_prf_bits(&keyseed,label_str,&data,64 * 8)?;
        
        let mut kck: Vec<u8> = Vec::new();
        kck.extend(key_buf[0..32].iter());
        trace_println!("kck:\n {:x?}", &kck);
        
        let mut pmk: Vec<u8> = Vec::new();
        pmk.extend(key_buf[32..64].iter());
        trace_println!("pmk:\n {:x?}", &pmk);

        let len = std::cmp::min(data.len(),16);
        let mut pmkid = vec![0u8;16];
        for i in (0..len){
            pmkid[i] = data[i];
        }
        trace_println!("pmkid:\n {:02x?}", &pmkid);

        let mut token_message = Vec::new();
        token_message.extend(&ss_hex);
        trace_println!("ss_hex:\n {:02x?}", &ss_hex);
        token_message.extend(&scalar.convert_to_octet_string()?);
        trace_println!("scalar:\n {:02x?}", &scalar.convert_to_octet_string()?);
        token_message.extend(&peer_scalar.convert_to_octet_string()?);
        trace_println!("peer_scalar:\n {:02x?}", &peer_scalar.convert_to_octet_string()?);
        token_message.extend(&element.convert_to_octet_string()?);
        trace_println!("element:\n {:02x?}", &element.convert_to_octet_string()?);
        token_message.extend(&peer_element.convert_to_octet_string()?);
        trace_println!("peer_element:\n {:02x?}", &peer_element.convert_to_octet_string()?);
       


        let mut token = vec![0u8;32];
        Self::hmac_sha256(&kck,&token_message,&mut token)?;
        trace_println!("token:\n {:02x?}", &token);


        Ok((kck,ss_hex,token))
    }

     pub fn confirm_exchange(self: &Self,peer_scalar: &BigInt, peer_element: &BigInt,password_element: &BigInt,private: &BigInt,scalar: &BigInt,element: &BigInt,
                            kck: &[u8],ss_hex: &[u8],peer_token: &[u8]) -> Result<()> {
        let mut peer_message = Vec::new();
        peer_message.extend(ss_hex);
        peer_message.extend(&peer_scalar.convert_to_octet_string()?);
        peer_message.extend(&scalar.convert_to_octet_string()?);
        peer_message.extend(&peer_element.convert_to_octet_string()?);
        peer_message.extend(&element.convert_to_octet_string()?);
    
        let mut peer_token_computed = vec![0u8;32];
        Self::hmac_sha256(&kck,&peer_message,&mut peer_token_computed)?;

        trace_println!(" Computed Token from Peer = {:02x?} \n", &peer_token_computed);
        trace_println!(" Received Token from Peer = {:02x?} \n", &peer_token);

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
}





