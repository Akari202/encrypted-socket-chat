mod elg {
    use std::fs;
    use log::debug;
    use num::{BigInt, BigUint};
    use crate::math::prime::is_prime;
    use serial_test::serial;
    use test_log::test;
    use crate::math::{modular_inverse, modular_pow, xgcd};
    use crate::math::point::Point;
    use rayon::prelude::*;
    use more_asserts as ma;
    use num::bigint::ToBigInt;
    use crate::elgamal::KeySet;
    use crate::elgamal::PrivateKey;
    use crate::elgamal::PublicKey;

    const INPUT: &str = "./src/elgamal.rs";
    const KEY_NAME: &str = "test_keys";
    const BIT_LENGTH: u64 = 64;

#[cfg(test)]
    fn make_or_get_key() {
        if !KeySet::keypair_exists(KEY_NAME).unwrap() {
            let keyset = KeySet::new(BIT_LENGTH);
            keyset.save_keys(KEY_NAME).unwrap();
        }
    }

#[test]
#[serial(elg)]
    fn test_elgamal() {
        let mut rng = rand::thread_rng();
        let input_plaintext = fs::read_to_string(INPUT).unwrap();
        make_or_get_key();
        let public_key = PublicKey::load_key(KEY_NAME).unwrap();
        let ciphertext = public_key.encrypt_string(&mut rng, &input_plaintext);
        let private_key = PrivateKey::load_key(KEY_NAME).unwrap();
        let plaintext = private_key.decrypt_sequence_to_string(&ciphertext).unwrap();
        assert_eq!(plaintext, input_plaintext);
    }


#[test]
#[serial(elg)]
    fn test_elgamal_short() {
        let mut rng = rand::thread_rng();
        let input = Point::new(BigInt::from(47u8), BigInt::from(97u8));
        make_or_get_key();
        let public_key = PublicKey::load_key(KEY_NAME).unwrap();
        let ciphertext = public_key.encrypt(&mut rng, &input);
        debug!("Ciphertext: {} Halfmask: {}", &ciphertext.0, &ciphertext.1);
        let private_key = PrivateKey::load_key(KEY_NAME).unwrap();
        let plaintext = private_key.decrypt(&ciphertext.0, &ciphertext.1).unwrap();
        debug!("Plaintext: {}", &plaintext);

        assert_eq!(plaintext, input);
    }
}

mod math {
    use std::fs;
    use log::debug;
    use num::{BigInt, BigUint};
    use crate::math::prime::is_prime;
    use serial_test::serial;
    use test_log::test;
    use crate::math::{modular_inverse, modular_pow, xgcd};
    use crate::math::point::Point;
    use rayon::prelude::*;
    use more_asserts as ma;
    use num::bigint::ToBigInt;

#[test]
    fn test_modular_inverse() {
        let q = BigInt::from(43u8);

        assert_eq!(modular_inverse(&BigInt::from(16u8), &q), BigUint::from(35u8));
        assert_eq!(modular_inverse(&BigInt::from(21u8), &q), BigUint::from(41u8));
        assert_eq!(modular_inverse(&BigInt::from(37u8), &q), BigUint::from(7u8));
        assert_eq!(modular_inverse(&BigInt::from(-8i8), &q), BigUint::from(16u8));
        assert_eq!(modular_inverse(&BigInt::from(-343i16), &BigInt::from(5u8)), BigUint::from(3u8));
    }

#[test]
    fn test_modular_pow() {
        let q = BigUint::from(840u16);

        assert_eq!(modular_pow(
                &BigUint::from(43u8),
                &BigUint::from(67u8),
                &q
        ),
        BigUint::from(547u16)
        );
        assert_eq!(modular_pow(
                &BigUint::from(4u8),
                &BigUint::from(80u8),
                &q
        ),
        BigUint::from(16u8)
        );
        assert_eq!(modular_pow(
                &BigUint::from(4u8),
                &BigUint::from(81u8),
                &q
        ),
        BigUint::from(64u8)
        );
    }

#[test]
    fn test_point_addition() {
        let test_point = Point::new_usize(32, 32);

        assert_eq!(Point::point_addition(
                &test_point,
                &test_point,
                &BigUint::from(43u8),
                &BigInt::from(4u8)
        ), Point::new_usize(31, 8));
        assert_eq!(Point::point_addition(
                &Point::new_usize(11, 17),
                &Point::new_usize(83, 23),
                &BigUint::from(97u8),
                &BigInt::from(2u8)
        ), Point::new_usize(67, 43));
    }

#[test]
    fn test_point_multiplication() {
        assert_eq!(Point::point_multiplication(
                5,
                &Point::new_usize(32, 32),
                &BigUint::from(43u8),
                &BigInt::from(4u8)
        ), Point::new_usize(26, 16));
    }

#[test]
    fn test_primes() {
        let number = "61737427114173267775731323796425561064149266411052180688680846252073237912944787878128967498662605431065348536621282084481362341".parse::<BigUint>().unwrap();
        assert!(is_prime(&number));
    }
}

mod rsa {
    use std::fs;
    use log::debug;
    use num::{BigInt, BigUint};
    use crate::math::prime::is_prime;
    use serial_test::serial;
    use test_log::test;
    use crate::math::{modular_inverse, modular_pow, xgcd};
    use crate::math::point::Point;
    use rayon::prelude::*;
    use more_asserts as ma;
    use num::bigint::ToBigInt;
    use crate::rsa::KeySet;
    use crate::rsa::Key;

    const INPUT: &str = "./src/rsa.rs";
    const KEY_NAME: &str = "test_keys";
    const SALT_BITS: u32 = 4;
    const BIT_LENGTH: u64 = 128;

#[cfg(test)]
    fn make_or_get_key() {
        if !KeySet::keypair_exists(KEY_NAME).unwrap() {
            let keyset = KeySet::new(SALT_BITS, BIT_LENGTH);
            keyset.save_keys(KEY_NAME).unwrap();
        }
    }

#[test]
#[serial(rsa)]
    fn test_rsa() {
        let mut rng = rand::thread_rng();
        let input_plaintext = fs::read_to_string(INPUT).unwrap();
        make_or_get_key();
        let public_key = Key::load_public_key(KEY_NAME).unwrap();
        let ciphertext = public_key.encrypt_string(&mut rng, &input_plaintext);
        let private_key = Key::load_private_key(KEY_NAME).unwrap();
        let plaintext = private_key.decrypt_sequence_to_string(&ciphertext).unwrap();
        assert_eq!(plaintext, input_plaintext);
    }

#[test]
#[serial(rsa)]
    fn test_rsa_short() {
        let mut rng = rand::thread_rng();
        let input = 45u8;
        make_or_get_key();
        let public_key = Key::load_public_key(KEY_NAME).unwrap();
        let ciphertext = public_key.encrypt(&mut rng, input);
        debug!("Ciphertext: {}", &ciphertext);
        let private_key = Key::load_private_key(KEY_NAME).unwrap();
        let plaintext = private_key.decrypt(&ciphertext).unwrap();
        debug!("Plaintext: {}", &plaintext);

        assert_eq!(plaintext, input);
    }

#[test]
#[serial(rsa)]
    fn test_rsa_key_loading() {
        let keyset = KeySet::new(SALT_BITS, BIT_LENGTH);
        keyset.save_keys(KEY_NAME).unwrap();
        let public_key = Key::load_public_key(KEY_NAME).unwrap();
        let private_key = Key::load_private_key(KEY_NAME).unwrap();

        assert_eq!(public_key, keyset.get_public_key());
        assert_eq!(private_key, keyset.get_private_key());
    }

#[test]
#[serial(rsa)]
    fn test_rsa_key_generation() {
        let keyset = KeySet::new(SALT_BITS, BIT_LENGTH);
        let private = keyset.get_private_key();
        let public = keyset.get_public_key();
        let e = public.get_exponent();
        let d = private.get_exponent();
        let phi = keyset.get_phi();
        let primes = keyset.get_primes();
        let p = primes.0;
        let q = primes.1;

        assert_eq!(
            xgcd(
                &e.to_bigint().unwrap(),
                &phi.to_bigint().unwrap()
            ).0,
            BigInt::from(1u8)
        );
        ma::assert_lt!(e, phi);
        // ma::assert_gt!(p, q);
        ma::assert_gt!(e, BigUint::from(1u8));
        assert_eq!((e * d) % phi, BigUint::from(1u8));
    }

#[test]
    fn test_rsa_decrypt() {
        let exponent = "5972318232184662818534657855621737571277286068078666649793550283924247797076600173939281818787359394403026459896653190335007799614591563221276639837983841972333802003997320297768848622815644973391769281870393538017740501411351041266408917078788473427609704238761228993510585840686384574383282303379820953762063950334302314875984006281425885391763913341220784051554637591650984586864663887689501907134781993708067907103855144195721271779341554179537064878523697570335522415646325958685244556320414141606231306257951455333114281153341089194204551522735441131257103024204928486981873600014013927205209042684557074561966118919414461491559908091650857239343415983318184952306903290923410008357862683310899990264857588747699184648921097973569568044329540312984534942061772478772563393529635946565998116995555176250052943813324160207082175863652954460255683112278647666089132489655576388991253021259724609761988692086238298612682416740554295058129539448147846088800158081694155943982357110272914628291665859542740382500879647261432217689588317079948268355990580039277479247226501778834653112023016536885335542917652121202427799424851418340504346702844335474953108869302490449748355665363773954437944927963678845733425769918259030595124253".parse::<BigUint>().unwrap();
        let modulus = "138160190604548622357326463778285144796611188508179165629198695713922847821040997387736926423532358853156069573684066408395836979647542279856267965076578556774034727121769283570376643908743001984178038625464165655160133865512076664834677443908422231918551777866464759812108458962606278097902284615814799098730810135213261846109200077538230939258747472165049955660690534360759116438174894884400595301056197501463341485303690287735610656054609049157896442267492964231231603443068571957061373980787497916854070285290280454700427336373637473533562899098310132516483148922456194229202629764955323242939564077097711611566410236466649906268979879215302450863300464583463178059566781956944158273513126964335460197225115755045796729840262758996811327865524072500225012386393808133852621589711639897703797587054310356454992581758845789583175681764698197176318685063173419372718357144051417961297932934259813883310251956304084199200267549688190016069693364792241266321482541291003969064904148078095307828267850543117144378675873122914791942038024427774188342449142548269918410487074986516096675253625014109869239001870463478768989062492767057672573426516067824547963100190383855987447010090176261585886303051264066913087726939128042499730346749".parse::<BigUint>().unwrap();
        let input = "50321378176660919196697331867341667476958089874532118490291495202007131324457551530257111077097053294121401718458940490932693054065773347416820098422330952905921191141991770370144578265975970392397508149136880123052947779727338000266138091774145875712196985188919084339358527248946749912579347262469382372852048091715145270256467769266728668770555127373509083411658396338478612285122095143050281120281547012499433344993973300423847721876729018114186207602294655161231460951378931250094065139884751039268479215671926792349810044886933829791375380829059145870529177485321989778795473742687913442103224451117819982319447268673262767335815246247869908325419688684828668721088198418020352205044848328594171614660154294747700837664589430141666463792270815641028438553635724811813226986103046800577007223493741766198477949635035952344006348342706263342243740050560980828810673448255080449973383214729887743597622868647234942386235923139338685875524170575892588403190508259815478731984805525007410580326950789049504707617795976458067214556176959160389030399442637509646572560194296137095423043344718490299029704881639046625948680256267402261357246420349545326873908549413727646463863401281973343949679427067887842978518667974593837451676335".parse::<BigUint>().unwrap();
        let key = Key::new(exponent, modulus, 0);
        let output = key.decrypt(&input).unwrap();
        assert_eq!(output, 89);
    }

#[test]
    fn test_rsa_encrypt() {
        let mut rng = rand::thread_rng();
        let exponent = "65537".parse::<BigUint>().unwrap();
        let modulus = "138160190604548622357326463778285144796611188508179165629198695713922847821040997387736926423532358853156069573684066408395836979647542279856267965076578556774034727121769283570376643908743001984178038625464165655160133865512076664834677443908422231918551777866464759812108458962606278097902284615814799098730810135213261846109200077538230939258747472165049955660690534360759116438174894884400595301056197501463341485303690287735610656054609049157896442267492964231231603443068571957061373980787497916854070285290280454700427336373637473533562899098310132516483148922456194229202629764955323242939564077097711611566410236466649906268979879215302450863300464583463178059566781956944158273513126964335460197225115755045796729840262758996811327865524072500225012386393808133852621589711639897703797587054310356454992581758845789583175681764698197176318685063173419372718357144051417961297932934259813883310251956304084199200267549688190016069693364792241266321482541291003969064904148078095307828267850543117144378675873122914791942038024427774188342449142548269918410487074986516096675253625014109869239001870463478768989062492767057672573426516067824547963100190383855987447010090176261585886303051264066913087726939128042499730346749".parse::<BigUint>().unwrap();
        let encrypted = "50321378176660919196697331867341667476958089874532118490291495202007131324457551530257111077097053294121401718458940490932693054065773347416820098422330952905921191141991770370144578265975970392397508149136880123052947779727338000266138091774145875712196985188919084339358527248946749912579347262469382372852048091715145270256467769266728668770555127373509083411658396338478612285122095143050281120281547012499433344993973300423847721876729018114186207602294655161231460951378931250094065139884751039268479215671926792349810044886933829791375380829059145870529177485321989778795473742687913442103224451117819982319447268673262767335815246247869908325419688684828668721088198418020352205044848328594171614660154294747700837664589430141666463792270815641028438553635724811813226986103046800577007223493741766198477949635035952344006348342706263342243740050560980828810673448255080449973383214729887743597622868647234942386235923139338685875524170575892588403190508259815478731984805525007410580326950789049504707617795976458067214556176959160389030399442637509646572560194296137095423043344718490299029704881639046625948680256267402261357246420349545326873908549413727646463863401281973343949679427067887842978518667974593837451676335".parse::<BigUint>().unwrap();
        let input = 89;
        let key = Key::new(exponent, modulus, 0);
        let output = key.encrypt(&mut rng, input);
        assert_eq!(output, encrypted);
    }
}

