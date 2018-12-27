use openssl::bn::{BigNum, BigNumContext};
use openssl::error::ErrorStack;

pub struct PedersenCommitment {
    pub p: BigNum,
    pub q: BigNum,
    pub g: BigNum,
    pub h: BigNum,
    pub ctx: BigNumContext
}

impl PedersenCommitment {
    pub fn new(security: i32) -> Result< PedersenCommitment, ErrorStack > {

        // create context to manage the bignum
        let mut ctx = BigNumContext::new()?;

        // generate prime number with 2*security bits
        let mut p = BigNum::new()?;
        p.generate_prime(2 * security, false, None, None)?;

        // generate q = 2p + 1
        let mut q = BigNum::new()?;
        let one = BigNum::from_u32(1)?;
        let two = BigNum::from_u32(2)?;
        let mut tmp = BigNum::new()?;
        tmp.checked_mul(&p, &two, &mut ctx)?;
        q.checked_add(&tmp, &one)?;

        // generate random BigNum between 1, p-1
        let g = BigNum::from_u32(1)?;
        let mut tmp2 = BigNum::new()?;
        tmp2.checked_sub(&p, &one)?;
        let mut tmp3 = BigNum::new()?;
        tmp3.checked_add(&g, &one)?;
        g.rand_range(&mut tmp2)?;

        // generate secret alpha between 1, p-1
        let alpha = BigNum::from_u32(1)?;
        let mut tmp4 = BigNum::new()?;
        tmp4.checked_sub(&p, &one)?;
        let mut tmp5 = BigNum::new()?;
        tmp5.checked_add(&g, &one)?;
        alpha.rand_range(&mut tmp4)?;

        // calculate h = pow(g, alpha, p)
        let mut h = BigNum::new()?;
        h.mod_exp(&g, &alpha, &p, &mut ctx)?;

        Ok(Self{p, q, g, h, ctx})
    }
}

fn pedersen_open(cmt: &mut PedersenCommitment, c: &BigNum, x: u32, args: &[BigNum]) -> Result< bool, ErrorStack > {
    let total = args.iter().fold(BigNum::new()?, |acc, x| {
        &acc + x
    });

    // res: open commitment
    let x1 = BigNum::from_u32(x)?;
    let mut res = BigNum::new()?;
    let mut tmp1 = BigNum::new()?;
    let mut tmp2 = BigNum::new()?;
    tmp1.mod_exp(&cmt.g, &x1, &cmt.q, &mut cmt.ctx)?;
    tmp2.mod_exp(&cmt.h, &total, &cmt.q, &mut cmt.ctx)?;
    res.mod_mul(&tmp1, &tmp2, &cmt.q, &mut cmt.ctx)?;

    Ok(&res == c)
}

fn pedersen_add(cmt: &mut PedersenCommitment, cm: &[BigNum]) -> Result<BigNum, ErrorStack> {
    let res = cm.iter().fold(BigNum::from_u32(1)?, |acc, x| {
        &acc * x
    });

    let mut tmp = BigNum::new()?;
    tmp.nnmod(&res, &cmt.q, &mut cmt.ctx)?;
    Ok(tmp)
}

fn pedersen_commit(cmt: &mut PedersenCommitment, x: u32) -> Result <(BigNum, BigNum), ErrorStack> {
    let one = BigNum::from_u32(1)?;
    // generate random number between 1, q-1
    let r = BigNum::from_u32(1)?;
    let mut tmp1 = BigNum::new()?;
    tmp1.checked_sub(&cmt.p, &one)?;
    let mut tmp2 = BigNum::new()?;
    tmp2.checked_add(&r, &one)?;
    r.rand_range(&mut tmp1)?;

    // c: calculate commitment
    let x1 = BigNum::from_u32(x)?;
    let mut c = BigNum::new()?;
    let mut tmp3 = BigNum::new()?;
    let mut tmp4 = BigNum::new()?;
    tmp3.mod_exp(&cmt.g, &x1, &cmt.q, &mut cmt.ctx)?;
    tmp4.mod_exp(&cmt.h, &r, &cmt.q, &mut cmt.ctx)?;
    c.mod_mul(&tmp3, &tmp4, &cmt.q, &mut cmt.ctx)?;

    Ok((c, r))
}

#[test]
fn test() {
    let mut commitment = PedersenCommitment::new(512).unwrap();

    let msg1 = 500;

    let (c1, r1) = pedersen_commit(&mut commitment, msg1).unwrap();

    println!("c1: {}, r1: {}", c1, r1)
}
