// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Amounts
//!
//! Defines a type `Amount` that can be used to express Bitcoin amounts in
//! different precisions and supports arithmetic and convertion to various
//! denominations.
//!
//!
//! Warning!
//!
//! In a few functions, this module supports convertion to and from floating-point numbers.
//! Please be aware of the risks of using floating-point numbers for financial applications.
//! These types of numbers do not give any guarantee to retain the precision
//! of the original amount when converting, or when doing arithmetic operations.
//!

use std::default;
use std::error;
use std::fmt::{self, Write};
use std::ops;
use std::str::FromStr;

use serde_json;

/// A set of denominations in which an Amount can be expressed.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Denomination {
    /// BTC
    Bitcoin,
    /// mBTC
    MilliBitcoin,
    /// uBTC
    MicroBitcoin,
    /// bits
    Bit,
    /// satoshi
    Satoshi,
    /// msat
    MilliSatoshi,
}

impl Denomination {
    /// The number of decimal places more than a satoshi.
    fn precision(self) -> i32 {
        match self {
            Denomination::Bitcoin => -8,
            Denomination::MilliBitcoin => -5,
            Denomination::MicroBitcoin => -2,
            Denomination::Bit => -2,
            Denomination::Satoshi => 0,
            Denomination::MilliSatoshi => 3,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Denomination::Bitcoin => "BTC",
            Denomination::MilliBitcoin => "mBTC",
            Denomination::MicroBitcoin => "uBTC",
            Denomination::Bit => "bits",
            Denomination::Satoshi => "satoshi",
            Denomination::MilliSatoshi => "msat",
        })
    }
}

impl FromStr for Denomination {
    type Err = ParseAmountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "BTC" => Ok(Denomination::Bitcoin),
            "mBTC" => Ok(Denomination::MilliBitcoin),
            "uBTC" => Ok(Denomination::MicroBitcoin),
            "bits" => Ok(Denomination::Bit),
            "satoshi" => Ok(Denomination::Satoshi),
            "msat" => Ok(Denomination::MilliSatoshi),
            d => Err(ParseAmountError::UnknownDenomination(d.to_owned())),
        }
    }
}

/// An error during `Amount` parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseAmountError {
    /// Amount is too big to fit in the data type.
    TooBig,
    /// Amount has higher precision than supported by the type.
    TooPrecise,
    /// Invalid number format.
    InvalidFormat,
    /// The denomination was unknown.
    UnknownDenomination(String),
}

impl fmt::Display for ParseAmountError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseAmountError::TooBig => write!(f, "amount is too big"),
            ParseAmountError::TooPrecise => write!(f, "amount has a too high precision"),
            ParseAmountError::InvalidFormat => write!(f, "invalid number format"),
            ParseAmountError::UnknownDenomination(ref d) => {
                write!(f, "unknown denomination: {}", d)
            }
        }
    }
}

impl error::Error for ParseAmountError {
    fn cause(&self) -> Option<&error::Error> {
        None
    }

    fn description(&self) -> &'static str {
        match *self {
            ParseAmountError::TooBig => "amount is too big",
            ParseAmountError::TooPrecise => "amount has a too high precision",
            ParseAmountError::InvalidFormat => "invalid number format",
            ParseAmountError::UnknownDenomination(_) => "unknown denomination",
        }
    }
}

// The inner type used to represent amounts.
// This is done to more easily change the underlying type in case this is desired in the future.
type Inner = i64;

/// Type to represent Bitcoin amounts.
#[derive(Copy, Clone, Hash)]
pub struct Amount(Inner);
// The Inner amount represents the number of satoshis.

impl Amount {
    /// Create a new Amount using `amount` as the Inner type.
    fn from_inner(amount: Inner) -> Amount {
        Amount(amount)
    }

    /// The zero amount.
    pub fn zero() -> Amount {
        Amount::from_inner(0)
    }

    /// Create an Amount with satoshi precision and the given number of satoshis.
    pub fn from_sat(satoshi: i64) -> Amount {
        Amount::from_inner(satoshi)
    }

    /// Get the number of satoshis in this amount.
    pub fn as_sat(self) -> i64 {
        self.0
    }

    /// The maximum value of an Amount.
    pub fn max_value() -> Amount {
        Amount::from_inner(Inner::max_value())
    }

    /// The minimum value of an amount.
    pub fn min_value() -> Amount {
        Amount::from_inner(Inner::min_value())
    }

    // Don't use the Inner type in the methods below.
    // Always use [Amount::from_sat] and [Amount::as_sat] instead.

    /// Convert from a value expressing bitcoins to an Amount.
    pub fn from_btc<T: IntoBtc>(btc: T) -> Amount {
        btc.into_btc()
    }

    /// Parse a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string.  If you want to parse a value with denomination,
    /// use `FromStr`.
    pub fn parse_denom(mut s: &str, denom: Denomination) -> Result<Amount, ParseAmountError> {
        if s.len() == 0 {
            return Err(ParseAmountError::InvalidFormat);
        }

        let negative = s.chars().nth(0).unwrap() == '-';
        if negative {
            if s.len() == 1 {
                return Err(ParseAmountError::InvalidFormat);
            }
            s = &s[1..];
        }

        let max_decimals = {
            // The difference in precision between native (satoshi)
            // and desired denomination.
            let precision_diff = -denom.precision();
            if precision_diff < 0 {
                // If precision diff is negative, this means we are parsing into a less
                // precise amount.  That is not allowed unless the last digits are zeroes
                // as many as the diffence in precision.
                let last_n = precision_diff.abs() as usize;
                if !s.chars().skip(s.len() - last_n).all(|d| d == '0') {
                    return Err(ParseAmountError::TooPrecise);
                }
                s = &s[0..s.len() - last_n];
                0
            } else {
                precision_diff
            }
        };

        let mut decimals = None;
        let mut value: i64 = 0; // as satoshis
        for c in s.as_bytes() {
            match *c {
                b'0'...b'9' => {
                    // Do `value = 10 * value + digit`, catching overflows.
                    match 10_i64.checked_mul(value) {
                        None => return Err(ParseAmountError::TooBig),
                        Some(n) => match n.checked_add((c - b'0').into()) {
                            None => return Err(ParseAmountError::TooBig),
                            Some(n) => value = n,
                        },
                    }
                    // Increment the decimal digit counter if past decimal.
                    decimals = match decimals {
                        None => None,
                        Some(d) if d == max_decimals => return Err(ParseAmountError::TooPrecise),
                        Some(d) => Some(d + 1),
                    }
                }
                b'.' => match decimals {
                    None => decimals = Some(0),
                    // Double decimal dot.
                    Some(_) => return Err(ParseAmountError::InvalidFormat),
                },
                _ => return Err(ParseAmountError::InvalidFormat),
            }
        }

        // Decimally shift left by `max_decimals - decimals`.
        let scalefactor = max_decimals - decimals.or_else(|| Some(0)).unwrap();
        for _ in 0..scalefactor {
            value = match 10_i64.checked_mul(value) {
                Some(v) => v,
                None => return Err(ParseAmountError::TooBig),
            };
        }

        if negative {
            value *= -1;
        }

        Ok(Amount::from_sat(value))
    }

    /// Express this Amount as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn as_float_denom(&self, denom: Denomination) -> f64 {
        f64::from_str(&self.to_string_in(denom)).unwrap()
    }

    /// Convert an amount in floating-point notation with a given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn from_float_denom(value: f64, denom: Denomination) -> Amount {
        let amt = value * 10_f64.powi(-denom.precision());
        Amount::from_sat(if value < 0.0 {
            (amt - 0.5) as i64
        } else {
            (amt + 0.5) as i64
        })
    }

    /// Format the value of this Amount in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn fmt_value_in(&self, f: &mut fmt::Write, denom: Denomination) -> fmt::Result {
        if denom.precision() > 0 {
            // add decimal point and zeroes
            let width = denom.precision() as usize;
            write!(f, "{}.{:0width$}", self.as_sat(), 0, width = width)?;
        } else if denom.precision() < 0 {
            // need to inject a comma in the numbered
            let nb_decimals = denom.precision().abs() as usize;
            let real = format!("{:0width$}", self.as_sat(), width = nb_decimals);
            if real.len() == nb_decimals {
                write!(f, "0.{}", &real[real.len() - nb_decimals..])?;
            } else {
                write!(
                    f,
                    "{}.{}",
                    &real[0..(real.len() - nb_decimals)],
                    &real[real.len() - nb_decimals..]
                )?;
            }
        } else {
            // denom.precision() == 0
            write!(f, "{}", self.as_sat())?;
        }
        Ok(())
    }

    /// Get a formatted string of this Amount in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn to_string_in(&self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        buf
    }

    /// Get a formatted string of this Amount in the given denomination, suffixed with the
    /// abbreviation for the denomination.
    pub fn to_string_denom(&self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        write!(buf, " {}", denom).unwrap();
        buf
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Amount({} satoshi)", self.as_sat())
    }
}

// No one should depend on a binding contract for Display for this type.
// Just using Bitcoin denominated string.
impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_value_in(f, Denomination::Bitcoin)?;
        write!(f, " {}", Denomination::Bitcoin)
    }
}

impl default::Default for Amount {
    fn default() -> Self {
        Amount::zero()
    }
}

impl ops::Add for Amount {
    type Output = Amount;

    fn add(self, rhs: Amount) -> Self::Output {
        Amount::from_inner(self.0 + rhs.0)
    }
}

impl ops::Sub for Amount {
    type Output = Amount;

    fn sub(self, rhs: Amount) -> Self::Output {
        Amount::from_inner(self.0 - rhs.0)
    }
}

impl ops::Mul<i64> for Amount {
    type Output = Amount;

    fn mul(self, rhs: i64) -> Self::Output {
        Amount::from_inner(self.0 * rhs)
    }
}

impl ops::Div for Amount {
    type Output = f64;

    fn div(self, rhs: Amount) -> Self::Output {
        self.0 as f64 / rhs.0 as f64
    }
}

impl ops::Div<f64> for Amount {
    type Output = Amount;

    fn div(self, rhs: f64) -> Self::Output {
        Amount::from_inner((self.0 as f64 / rhs) as Inner)
    }
}

impl PartialEq for Amount {
    fn eq(&self, other: &Amount) -> bool {
        PartialEq::eq(&self.0, &other.0)
    }
}
impl Eq for Amount {}

impl PartialOrd for Amount {
    fn partial_cmp(&self, other: &Amount) -> Option<::std::cmp::Ordering> {
        PartialOrd::partial_cmp(&self.0, &other.0)
    }
}

impl Ord for Amount {
    fn cmp(&self, other: &Amount) -> ::std::cmp::Ordering {
        Ord::cmp(&self.0, &other.0)
    }
}

impl FromStr for Amount {
    type Err = ParseAmountError;

    /// Parses amounts with denomination suffix like they are produced with
    /// `to_string_denom()`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.splitn(3, " ");
        let amt_str = split.next().unwrap();
        let denom_str = split.next().ok_or(ParseAmountError::InvalidFormat)?;
        if split.next().is_some() {
            return Err(ParseAmountError::InvalidFormat);
        }

        Ok(Amount::parse_denom(amt_str, denom_str.parse()?)?)
    }
}

/// A trait used to convert BTC-denominated value types into Amounts
/// Can be used with the [Amount::from_btc] constructor.
pub trait IntoBtc {
    /// Convert the given BTC-denominated value into an Amount.
    fn into_btc(self) -> Amount;
}

impl IntoBtc for f64 {
    fn into_btc(self) -> Amount {
        Amount::from_float_denom(self, Denomination::Bitcoin)
    }
}

impl<'a> IntoBtc for &'a f64 {
    fn into_btc(self) -> Amount {
        f64::into_btc(*self)
    }
}

impl IntoBtc for serde_json::value::Number {
    fn into_btc(self) -> Amount {
        Amount::parse_denom(&self.to_string(), Denomination::Bitcoin).unwrap()
    }
}

impl<'a> IntoBtc for &'a serde_json::value::Number {
    fn into_btc(self) -> Amount {
        Amount::parse_denom(&self.to_string(), Denomination::Bitcoin).unwrap()
    }
}

pub mod serde {
    // methods are implementation of a standardized serde-specific signature
    #![allow(missing_docs)]

    //! This module adds serde serialization and deserialization support for Amounts.
    //! Since there is not a default way to serialize and deserialize Amounts, multiple
    //! ways are supported and it's up to the user to decide which serialiation to use.
    //! The provided modules can be used as follows:
    //!
    //! ```rust,ignore
    //! use serde::{Serialize, Deserialize};
    //! use bitcoin::Amount;
    //!
    //! #[derive(Serialize, Deserialize)]
    //! pub struct HasAmount {
    //!     #[serde(with = "bitcoin::util::amount::serde::as_btc")]
    //!     pub amount: Amount,
    //! }
    //! ```

    pub mod as_sat {
        //! Serialize and deserialize [Amount] as real numbers denominated in satoshi.
        //! Use with `#[serde(with = "amount::serde::as_sat")]`.

        use amount::Amount;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(a: &Amount, s: S) -> Result<S::Ok, S::Error> {
            i64::serialize(&a.as_sat(), s)
        }

        pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Amount, D::Error> {
            Ok(Amount::from_sat(i64::deserialize(d)?))
        }

        pub mod opt {
            //! Serialize and deserialize [Optoin<Amount>] as real numbers denominated in satoshi.
            //! Use with `#[serde(default, with = "amount::serde::as_sat::opt")]`.

            use amount::Amount;
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(a: &Option<Amount>, s: S) -> Result<S::Ok, S::Error> {
                match *a {
                    Some(a) => s.serialize_some(&a.as_sat()),
                    None => s.serialize_none(),
                }
            }

            pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Option<Amount>, D::Error> {
                Ok(Some(Amount::from_sat(i64::deserialize(d)?)))
            }
        }
    }

    pub mod as_btc {
        //! Serialize and deserialize [Amount] as JSON numbers denominated in BTC.
        //! Use with `#[serde(with = "amount::serde::as_btc")]`.

        use amount::{Amount, Denomination};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        pub fn serialize<S: Serializer>(a: &Amount, s: S) -> Result<S::Ok, S::Error> {
            f64::serialize(&a.as_float_denom(Denomination::Bitcoin), s)
        }

        pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Amount, D::Error> {
            Ok(Amount::from_btc(f64::deserialize(d)?))
        }

        pub mod opt {
            //! Serialize and deserialize [Option<Amount>] as JSON numbers denominated in BTC.
            //! Use with `#[serde(default, with = "amount::serde::as_btc::opt")]`.

            use amount::{Amount, Denomination};
            use serde::{Deserialize, Deserializer, Serializer};

            pub fn serialize<S: Serializer>(a: &Option<Amount>, s: S) -> Result<S::Ok, S::Error> {
                match *a {
                    Some(a) => s.serialize_some(&a.as_float_denom(Denomination::Bitcoin)),
                    None => s.serialize_none(),
                }
            }

            pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Option<Amount>, D::Error> {
                Ok(Some(Amount::from_btc(f64::deserialize(d)?)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[cfg(feature = "serde")]
    use serde_test;

    // Be aware of usage of inner here.
    static ONE_SAT: Amount = Amount(1);
    static ONE_BTC: Amount = Amount(100_000_000);

    #[test]
    fn add_sub_mul_div() {
        assert_eq!(Amount::from_btc(0.15) + Amount::from_btc(0.015), Amount::from_sat(16_500_000));
        assert_eq!(Amount::from_btc(0.15) - Amount::from_btc(0.015), Amount::from_sat(13_500_000));

        assert_eq!(Amount::from_btc(0.014) * 3, Amount::from_sat(4_200_000));
        assert_eq!(Amount::from_btc(0.014) * -3, Amount::from_sat(-4_200_000));

        assert_eq!((Amount::from_btc(0.225) / Amount::from_sat(7_500_000)) as usize, 3)
    }

    #[test]
    fn into_btc() {
        let amt: Amount = 0.25.into_btc(); // type annotaion needed
        assert_eq!(amt.as_sat(), 25_000_000);
        let amt: Amount = Amount::from_btc(0.25);
        assert_eq!(amt.as_sat(), 25_000_000);
    }

    #[test]
    fn as_float() {
        use super::Denomination as D;

        assert_eq!(Amount::from_btc(2.5).as_float_denom(D::Bitcoin), 2.5);
        assert_eq!(Amount::from_btc(2.5).as_float_denom(D::MilliBitcoin), 2500.0);
        assert_eq!(Amount::from_btc(2.5).as_float_denom(D::Satoshi), 250000000.0);
        assert_eq!(Amount::from_btc(2.5).as_float_denom(D::MilliSatoshi), 250000000000.0);

        assert_eq!(Amount::from_btc(-2.5).as_float_denom(D::Bitcoin), -2.5);
        assert_eq!(Amount::from_btc(-2.5).as_float_denom(D::MilliBitcoin), -2500.0);
        assert_eq!(Amount::from_btc(-2.5).as_float_denom(D::Satoshi), -250000000.0);
        assert_eq!(Amount::from_btc(-2.5).as_float_denom(D::MilliSatoshi), -250000000000.0);

        let btc = move |f| Amount::from_btc(f);
        assert_eq!(&btc(0.0012).to_float_in(D::Bitcoin).to_string(), "0.0012")
    }

    #[test]
    fn parsing() {
        use super::ParseAmountError as E;
        let btc = Denomination::Bitcoin;
        let p = Amount::parse_denom;

        assert_eq!(p("x", btc), Err(E::InvalidFormat));
        assert_eq!(p("-", btc), Err(E::InvalidFormat));
        assert_eq!(p("-0.0-", btc), Err(E::InvalidFormat));
        assert_eq!(p("-0.0 ", btc), Err(E::InvalidFormat));
        assert_eq!(p("0.000.000", btc), Err(E::InvalidFormat));
        let more_than_max = format!("1{}", Amount::max_value());
        assert_eq!(p(&more_than_max, btc), Err(E::TooBig));
        assert_eq!(p("0.000000042", btc), Err(E::TooPrecise));

        assert_eq!(p("1", btc), Ok(Amount::from_sat(1_000_000_00)));
        assert_eq!(p("-1", btc), Ok(Amount::from_sat(-1_000_000_00)));
        assert_eq!(p("1.1", btc), Ok(Amount::from_sat(1_100_000_00)));
        assert_eq!(p("-12345678.12345678", btc), Ok(Amount::from_sat(-12_345_678__123_456_78)));
        assert_eq!(
            p("12345678901.12345678", btc),
            Ok(Amount::from_sat(12_345_678_901__123_456_78))
        );
    }

    #[test]
    fn to_string() {
        assert_eq!(ONE_BTC.to_string_in(Denomination::Bitcoin), "1.00000000");
        assert_eq!(ONE_BTC.to_string_in(Denomination::Satoshi), "100000000");
        assert_eq!(ONE_SAT.to_string_in(Denomination::Bitcoin), "0.00000001");
        assert_eq!(Amount::from_sat(42).to_string_in(Denomination::Bitcoin), "0.00000042");

        assert_eq!(ONE_BTC.to_string_denom(Denomination::Bitcoin), "1.00000000 BTC");
        assert_eq!(ONE_BTC.to_string_denom(Denomination::Satoshi), "100000000 satoshi");
        assert_eq!(ONE_SAT.to_string_denom(Denomination::Bitcoin), "0.00000001 BTC");
        assert_eq!(Amount::from_sat(42).to_string_denom(Denomination::Bitcoin), "0.00000042 BTC");
    }

    #[test]
    fn from_str() {
        use super::ParseAmountError as E;
        let p = Amount::from_str;

        assert_eq!(p("x BTC"), Err(E::InvalidFormat));
        assert_eq!(p("5 BTC BTC"), Err(E::InvalidFormat));
        assert_eq!(p("5 5 BTC"), Err(E::InvalidFormat));

        assert_eq!(p("5 BCH"), Err(E::UnknownDenomination("BCH".to_owned())));

        assert_eq!(p("0.123456789 BTC"), Err(E::TooPrecise));
        assert_eq!(p("0.1 satoshi"), Err(E::TooPrecise));
        assert_eq!(p("0.123456 mBTC"), Err(E::TooPrecise));
        assert_eq!(p("1.001 bits"), Err(E::TooPrecise));
        assert_eq!(p("100000000000 BTC"), Err(E::TooBig));

        assert_eq!(p("0.00253583 BTC"), Ok(Amount::from_sat(253583)));
        assert_eq!(p("5 satoshi"), Ok(Amount::from_sat(5)));
        assert_eq!(p("0.10000000 BTC"), Ok(Amount::from_sat(100_000_00)));
        assert_eq!(p("100 bits"), Ok(Amount::from_sat(10_000)));
    }

    #[test]
    fn to_string_denom_from_str_roundtrip() {
        use super::Denomination as D;

        let amt = Amount::from_sat(42);
        assert_eq!(Amount::from_str(&amt.to_string_denom(D::Bitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_denom(D::MilliBitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_denom(D::MicroBitcoin)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_denom(D::Bit)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_denom(D::Satoshi)), Ok(amt));
        assert_eq!(Amount::from_str(&amt.to_string_denom(D::MilliSatoshi)), Ok(amt));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_sat() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(with = "::util::amount::serde::as_sat")]
            pub amt: Amount,
        }

        serde_test::assert_tokens(
            &T {
                amt: Amount::from_sat(123456789),
            },
            &[
                serde_test::Token::Struct {
                    name: "T",
                    len: 1,
                },
                serde_test::Token::Str("amt"),
                serde_test::Token::I64(123456789),
                serde_test::Token::StructEnd,
            ],
        );

        serde_test::assert_tokens(
            &T {
                amt: Amount::from_sat(-12345678),
            },
            &[
                serde_test::Token::Struct {
                    name: "T",
                    len: 1,
                },
                serde_test::Token::Str("amt"),
                serde_test::Token::I64(-12345678),
                serde_test::Token::StructEnd,
            ],
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_btc() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(with = "::util::amount::serde::as_btc")]
            pub amt: Amount,
        }

        serde_test::assert_tokens(
            &T {
                amt: Amount::from_sat(2__500_000_00),
            },
            &[
                serde_test::Token::Struct {
                    name: "T",
                    len: 1,
                },
                serde_test::Token::Str("amt"),
                serde_test::Token::F64(2.5),
                serde_test::Token::StructEnd,
            ],
        );

        serde_test::assert_tokens(
            &T {
                amt: Amount::from_sat(-12345678_90000000),
            },
            &[
                serde_test::Token::Struct {
                    name: "T",
                    len: 1,
                },
                serde_test::Token::Str("amt"),
                serde_test::Token::F64(-12345678.9),
                serde_test::Token::StructEnd,
            ],
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_btc_opt() {
        use serde::{Deserialize, Serialize};
        use serde_json;

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(default, with = "::util::amount::serde::as_btc::opt")]
            pub amt: Option<Amount>,
        }

        let with = T {
            amt: Some(Amount::from_sat(2__500_000_00)),
        };
        let without = T {
            amt: None,
        };

        let t: T = serde_json::from_str("{\"amt\":2.5}").unwrap();
        assert_eq!(t, with);

        let t: T = serde_json::from_str("{}").unwrap();
        assert_eq!(t, without);

        let value_with: serde_json::Value = serde_json::from_str("{\"amt\": 2.5}").unwrap();
        assert_eq!(with, serde_json::from_value(value_with).unwrap());

        let value_without: serde_json::Value = serde_json::from_str("{}").unwrap();
        assert_eq!(without, serde_json::from_value(value_without).unwrap());
    }
}
