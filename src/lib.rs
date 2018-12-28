use openssl::bn::{BigNum, BigNumContext};
use openssl::error::ErrorStack;
use std::fmt;

pub struct PedersenCommitment {
    p: BigNum,
    q: BigNum,
    g: BigNum,
    h: BigNum,
    ctx: BigNumContext,
}

impl fmt::Debug for PedersenCommitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PedersenCommitment{{p: {}, \nq: {}, \ng: {}, \nh: {}}}",
            self.p, self.q, self.g, self.h
        )
    }
}

impl PedersenCommitment {
    pub fn new(security: i32) -> Result<PedersenCommitment, ErrorStack> {
        // create context to manage the bignum
        let mut ctx = BigNumContext::new()?;
        // generate prime number with 2*security bits
        let mut p = BigNum::new()?;
        p.generate_prime(2 * security, false, None, None)?;
        // calculate q from p, where q = 2p + 1
        let q = calculate_q(&p, &mut ctx)?;
        // generate random g
        let g = gen_random(&p)?;
        // generate random secret alpha
        let alpha = gen_random(&p)?;
        // calculate h = pow(g, alpha, p)
        let mut h = BigNum::new()?;
        h.mod_exp(&g, &alpha, &p, &mut ctx)?;
        Ok(Self { p, q, g, h, ctx })
    }

    pub fn open(&mut self, c: &BigNum, x: u32, args: &[&BigNum]) -> Result<bool, ErrorStack> {
        let total = args.iter().fold(BigNum::new()?, |acc, x| &acc + *x);
        let res = self.helper(x, &total)?;
        Ok(&res == c)
    }

    pub fn add(&mut self, cm: &[&BigNum]) -> Result<BigNum, ErrorStack> {
        let res = cm.iter().fold(BigNum::from_u32(1)?, |acc, x| &acc * *x);
        let mut tmp = BigNum::new()?;
        tmp.nnmod(&res, &self.q, &mut self.ctx)?;
        Ok(tmp)
    }

    pub fn commit(&mut self, x: u32) -> Result<(BigNum, BigNum), ErrorStack> {
        let r = gen_random(&self.q)?;
        let c = self.helper(x, &r)?;
        Ok((c, r))
    }

    fn helper(&mut self, x: u32, r: &BigNum) -> Result<BigNum, ErrorStack> {
        let x1 = BigNum::from_u32(x)?;
        let mut c = BigNum::new()?;
        let mut tmp3 = BigNum::new()?;
        let mut tmp4 = BigNum::new()?;
        tmp3.mod_exp(&self.g, &x1, &self.q, &mut self.ctx)?;
        tmp4.mod_exp(&self.h, r, &self.q, &mut self.ctx)?;
        c.mod_mul(&tmp3, &tmp4, &self.q, &mut self.ctx)?;
        Ok(c)
    }
}

fn gen_random(limit: &BigNum) -> Result<BigNum, ErrorStack> {
    // generate random bignum between 1, limit-1
    let one = BigNum::from_u32(1)?;
    let mut r = BigNum::new()?;
    let mut tmp1 = BigNum::new()?;
    tmp1.checked_sub(limit, &one)?;
    let mut tmp2 = BigNum::new()?;
    tmp2.checked_add(&r, &one)?;
    tmp1.rand_range(&mut r)?;
    Ok(r)
}

fn calculate_q(p: &BigNum, ctx: &mut BigNumContext) -> Result<BigNum, ErrorStack> {
    // generate q = 2p + 1
    let mut q = BigNum::new()?;
    let one = BigNum::from_u32(1)?;
    let two = BigNum::from_u32(2)?;
    let mut tmp = BigNum::new()?;
    tmp.checked_mul(p, &two, ctx)?;
    q.checked_add(&tmp, &one)?;
    Ok(q)
}

#[test]
fn test_basic() {
    let mut commitment = PedersenCommitment::new(512).unwrap();
    println!("commitment {:#?}", commitment);

    let msg1 = 500;
    let msg2 = 100;
    let msg3 = 600;

    let (c1, r1) = commitment.commit(msg1).unwrap();
    let (c2, r2) = commitment.commit(msg2).unwrap();
    let (c3, r3) = commitment.commit(msg3).unwrap();

    println!();
    println!("c1: {}, \nr1: {}\n", c1, r1);
    println!("c2: {}, \nr2: {}\n", c2, r2);
    println!("c3: {}, \nr3: {}\n", c3, r3);

    let add_cm = commitment.add(&[&c1, &c2, &c3]).unwrap();
    println!("add_cm: {}\n", add_cm);

    let res = commitment
        .open(&add_cm, msg1 + msg2 + msg3, &[&r1, &r2, &r3])
        .unwrap();
    assert_eq!(res, true)
}
