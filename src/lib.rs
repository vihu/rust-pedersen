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
        let g = BigNum::new()?;
        let mut tmp2 = BigNum::new()?;
        tmp2.checked_sub(&p, &one)?;
        let mut tmp3 = BigNum::new()?;
        tmp3.checked_add(&g, &one)?;
        g.rand_range(&mut tmp2)?;

        // generate secret alpha between 1, p-1
        let alpha = BigNum::new()?;
        let mut tmp4 = BigNum::new()?;
        tmp4.checked_sub(&p, &one)?;
        let mut tmp5 = BigNum::new()?;
        tmp5.checked_add(&g, &one)?;
        alpha.rand_range(&mut tmp4)?;

        // calculate h = pow(g, alpha, p)
        let mut h = BigNum::new()?;
        h.mod_exp(&g, &alpha, &p, &mut ctx)?;

        Ok(PedersenCommitment {
            p: p,
            q: q,
            g: g,
            h: h,
            ctx: ctx
        })
    }
}

