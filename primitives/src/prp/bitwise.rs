use crate::{Prp, NewPrp};

pub trait BitwisePrp<const N: usize>: Sized {
    fn bitwise_shuffle(self, prp: &NewPrp<u8, N>) -> Self;
    fn bitwise_inverse_shuffle(self, prp: &NewPrp<u8, N>) -> Self;
}

impl BitwisePrp<32> for u32 {
    fn bitwise_shuffle(self, prp: &NewPrp<u8, 32>) -> Self {
        let mut output: Self = 0;
    
        for (i, &p) in prp.forward() {
            let bit = (self >> p) & 1;
            output |= bit << i;
        }
    
        output 
    }

    fn bitwise_inverse_shuffle(self, prp: &NewPrp<u8, 32>) -> Self {
        let mut output: Self = 0;
    
        for (i, &p) in prp.inverse() {
            let bit = (self >> p) & 1;
            output |= bit << i;
        }
    
        output
    }
}

impl BitwisePrp<8> for u8 {
    fn bitwise_shuffle(self, prp: &NewPrp<u8, 8>) -> Self {
        let mut output: Self = 0;
    
        for (i, &p) in prp.forward() {
            let bit = (self >> p) & 1;
            output |= bit << i;
        }
    
        output
    }

    fn bitwise_inverse_shuffle(self, prp: &NewPrp<u8, 8>) -> Self {
        let mut output: Self = 0;
    
        for (i, &p) in prp.inverse() {
            let bit = (self >> p) & 1;
            output |= bit << i;
        }
    
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrpGenerator;

    struct StaticPrpGenerator {
        perm: [u8; 8]
    }

    impl PrpGenerator<u8, 8> for StaticPrpGenerator {
        fn generate(self) -> crate::NewPrp<u8, 8> {
            let mut inverse: [u8; 8] = [0; 8];

            for (index, val) in self.perm.iter().enumerate() {
                inverse[*val as usize] = index as u8;
            }
            crate::NewPrp {
                forward: self.perm,
                inverse
            }
        }
    }

    #[test]
    fn test_forward() {
        let gen = StaticPrpGenerator {
            perm: [1, 3, 2, 7, 6, 4, 0, 5]
        };
        let prp = PrpGenerator::generate(gen);
        let input = 0b00110110u8;
        assert_eq!(input, input.bitwise_shuffle(&prp).bitwise_inverse_shuffle(&prp));
        assert_eq!(0b10100101, input.bitwise_shuffle(&prp));
    }
}