use openssl::bn::{BigNum, BigNumContext};
use openssl::error::ErrorStack;

// Why I do what I do, I don't know
pub struct Verifier {
    pub p: BigNum,
    pub q: BigNum,
    pub g: BigNum,
    pub h: BigNum,
    pub ctx: BigNumContext
}

pub struct Prover {
    pub p: BigNum,
    pub q: BigNum,
    pub g: BigNum,
    pub h: BigNum,
    pub ctx: BigNumContext
}

impl Verifier {
    pub fn new(security: i32) -> Result< Verifier, ErrorStack > {

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

        Ok(Verifier {
            p: p,
            q: q,
            g: g,
            h: h,
            ctx: ctx
        })
    }

    pub fn add(&mut self, cm: &[BigNum]) -> Result< BigNum, ErrorStack> {
        // XXX: this is most definitely *wrong*
        let one = BigNum::from_u32(1)?;
        let mut res = BigNum::new()?;
        for c in cm {
            res.checked_mul(&one, &c, &mut self.ctx)?;
        }
        let mut tmp = BigNum::new()?;
        tmp.nnmod(&res, &self.q, &mut self.ctx)?;
        Ok(tmp)
    }

    // pub fn open(&mut self, c: BigNum, x: BigNum, r: &[BigNum]) -> Result< BigNum, ErrorStack > {
    //     // Do this
    // }
}

impl Prover {
    pub fn new(p: BigNum,
               q: BigNum,
               g: BigNum,
               h: BigNum,
               ctx: BigNumContext) -> Result< Prover, ErrorStack > {
        Ok(Prover {
            p: p,
            q: q,
            g: g,
            h: h,
            ctx: ctx
        })
    }

    pub fn commit(&mut self, x: u32) -> Result <(BigNum, BigNum), ErrorStack> {
        let one = BigNum::from_u32(1)?;
        // generate random number between 1, q-1
        let r = BigNum::new()?;
        let mut tmp1 = BigNum::new()?;
        tmp1.checked_sub(&self.p, &one)?;
        let mut tmp2 = BigNum::new()?;
        tmp2.checked_add(&r, &one)?;
        r.rand_range(&mut tmp1)?;

        // c: calculate commitment
        let x1 = BigNum::from_u32(x)?;
        let mut c = BigNum::new()?;
        let mut tmp3 = BigNum::new()?;
        let mut tmp4 = BigNum::new()?;
        tmp3.mod_exp(&self.g, &x1, &self.q, &mut self.ctx)?;
        tmp4.mod_exp(&self.h, &r, &self.q, &mut self.ctx)?;
        c.mod_mul(&tmp3, &tmp4, &self.q, &mut self.ctx)?;

        Ok((c, r))

    }
}
