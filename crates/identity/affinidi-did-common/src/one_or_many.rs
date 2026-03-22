use serde::{Deserialize, Serialize};

/// One or many.
///
/// Serializes/deserializes into/from either a value, or an array of values.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    /// A single value.
    One(T),

    /// An array of values.
    Many(Vec<T>),
}

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl<T> OneOrMany<T> {
    pub fn any<F>(&self, f: F) -> bool
    where
        F: Fn(&T) -> bool,
    {
        match self {
            Self::One(value) => f(value),
            Self::Many(values) => values.iter().any(f),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(values) => values.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::One(_) => false,
            Self::Many(values) => values.is_empty(),
        }
    }

    pub fn contains(&self, x: &T) -> bool
    where
        T: PartialEq<T>,
    {
        match self {
            Self::One(value) => x == value,
            Self::Many(values) => values.contains(x),
        }
    }

    pub fn as_slice(&self) -> &[T] {
        match self {
            Self::One(t) => std::slice::from_ref(t),
            Self::Many(l) => l.as_slice(),
        }
    }

    pub fn first(&self) -> Option<&T> {
        match self {
            Self::One(value) => Some(value),
            Self::Many(values) => values.first(),
        }
    }

    pub fn to_single(&self) -> Option<&T> {
        match self {
            Self::One(value) => Some(value),
            Self::Many(values) => values.first(),
        }
    }

    pub fn to_single_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::One(value) => Some(value),
            Self::Many(values) => values.first_mut(),
        }
    }

    pub fn into_single(self) -> Option<T> {
        match self {
            Self::One(value) => Some(value),
            Self::Many(values) => {
                let mut it = values.into_iter();
                let value = it.next()?;
                if it.next().is_none() {
                    Some(value)
                } else {
                    None
                }
            }
        }
    }

    pub fn into_vec(self) -> Vec<T> {
        match self {
            Self::One(t) => vec![t],
            Self::Many(v) => v,
        }
    }
}

// consuming iterator
impl<T> IntoIterator for OneOrMany<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::One(value) => vec![value].into_iter(),
            Self::Many(values) => values.into_iter(),
        }
    }
}

// non-consuming iterator
impl<'a, T> IntoIterator for &'a OneOrMany<T> {
    type Item = &'a T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            OneOrMany::One(value) => vec![value].into_iter(),
            OneOrMany::Many(values) => values.iter().collect::<Vec<Self::Item>>().into_iter(),
        }
    }
}

/// One or many reference(s).
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum OneOrManyRef<'a, T> {
    One(&'a T),
    Many(&'a [T]),
}

impl<'a, T> OneOrManyRef<'a, T> {
    pub fn from_slice(s: &'a [T]) -> Self {
        match s {
            [t] => Self::One(t),
            _ => Self::Many(s),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Many([]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- OneOrMany: default ---

    #[test]
    fn default_is_empty_many() {
        let v: OneOrMany<i32> = OneOrMany::default();
        assert!(matches!(v, OneOrMany::Many(ref v) if v.is_empty()));
    }

    // --- OneOrMany: len ---

    #[test]
    fn len_one() {
        assert_eq!(OneOrMany::One(42).len(), 1);
    }

    #[test]
    fn len_many() {
        assert_eq!(OneOrMany::Many(vec![1, 2, 3]).len(), 3);
    }

    #[test]
    fn len_many_empty() {
        assert_eq!(OneOrMany::<i32>::Many(vec![]).len(), 0);
    }

    // --- OneOrMany: is_empty ---

    #[test]
    fn is_empty_one_is_false() {
        assert!(!OneOrMany::One(42).is_empty());
    }

    #[test]
    fn is_empty_many_empty() {
        assert!(OneOrMany::<i32>::Many(vec![]).is_empty());
    }

    #[test]
    fn is_empty_many_nonempty() {
        assert!(!OneOrMany::Many(vec![1]).is_empty());
    }

    // --- OneOrMany: any ---

    #[test]
    fn any_one_true() {
        assert!(OneOrMany::One(42).any(|x| *x == 42));
    }

    #[test]
    fn any_one_false() {
        assert!(!OneOrMany::One(42).any(|x| *x == 99));
    }

    #[test]
    fn any_many_true() {
        assert!(OneOrMany::Many(vec![1, 2, 3]).any(|x| *x == 2));
    }

    #[test]
    fn any_many_false() {
        assert!(!OneOrMany::Many(vec![1, 2, 3]).any(|x| *x == 99));
    }

    // --- OneOrMany: contains ---

    #[test]
    fn contains_one_found() {
        assert!(OneOrMany::One("hello").contains(&"hello"));
    }

    #[test]
    fn contains_one_not_found() {
        assert!(!OneOrMany::One("hello").contains(&"world"));
    }

    #[test]
    fn contains_many_found() {
        assert!(OneOrMany::Many(vec!["a", "b"]).contains(&"b"));
    }

    #[test]
    fn contains_many_not_found() {
        assert!(!OneOrMany::Many(vec!["a", "b"]).contains(&"c"));
    }

    // --- OneOrMany: as_slice ---

    #[test]
    fn as_slice_one() {
        let v = OneOrMany::One(42);
        assert_eq!(v.as_slice(), &[42]);
    }

    #[test]
    fn as_slice_many() {
        let v = OneOrMany::Many(vec![1, 2]);
        assert_eq!(v.as_slice(), &[1, 2]);
    }

    // --- OneOrMany: first ---

    #[test]
    fn first_one() {
        assert_eq!(OneOrMany::One(42).first(), Some(&42));
    }

    #[test]
    fn first_many() {
        assert_eq!(OneOrMany::Many(vec![10, 20]).first(), Some(&10));
    }

    #[test]
    fn first_many_empty() {
        assert_eq!(OneOrMany::<i32>::Many(vec![]).first(), None);
    }

    // --- OneOrMany: to_single ---

    #[test]
    fn to_single_one() {
        assert_eq!(OneOrMany::One(42).to_single(), Some(&42));
    }

    #[test]
    fn to_single_many_single_element() {
        assert_eq!(OneOrMany::Many(vec![42]).to_single(), Some(&42));
    }

    #[test]
    fn to_single_many_empty() {
        assert_eq!(OneOrMany::<i32>::Many(vec![]).to_single(), None);
    }

    // --- OneOrMany: to_single_mut ---

    #[test]
    fn to_single_mut_one() {
        let mut v = OneOrMany::One(42);
        *v.to_single_mut().unwrap() = 99;
        assert_eq!(v, OneOrMany::One(99));
    }

    #[test]
    fn to_single_mut_many() {
        let mut v = OneOrMany::Many(vec![1, 2]);
        *v.to_single_mut().unwrap() = 99;
        assert_eq!(v, OneOrMany::Many(vec![99, 2]));
    }

    #[test]
    fn to_single_mut_many_empty() {
        let mut v = OneOrMany::<i32>::Many(vec![]);
        assert!(v.to_single_mut().is_none());
    }

    // --- OneOrMany: into_single ---

    #[test]
    fn into_single_one() {
        assert_eq!(OneOrMany::One(42).into_single(), Some(42));
    }

    #[test]
    fn into_single_many_single() {
        assert_eq!(OneOrMany::Many(vec![42]).into_single(), Some(42));
    }

    #[test]
    fn into_single_many_multiple() {
        assert_eq!(OneOrMany::Many(vec![1, 2]).into_single(), None);
    }

    #[test]
    fn into_single_many_empty() {
        assert_eq!(OneOrMany::<i32>::Many(vec![]).into_single(), None);
    }

    // --- OneOrMany: into_vec ---

    #[test]
    fn into_vec_one() {
        assert_eq!(OneOrMany::One(42).into_vec(), vec![42]);
    }

    #[test]
    fn into_vec_many() {
        assert_eq!(OneOrMany::Many(vec![1, 2, 3]).into_vec(), vec![1, 2, 3]);
    }

    // --- OneOrMany: consuming iterator ---

    #[test]
    fn into_iter_one() {
        let v: Vec<i32> = OneOrMany::One(42).into_iter().collect();
        assert_eq!(v, vec![42]);
    }

    #[test]
    fn into_iter_many() {
        let v: Vec<i32> = OneOrMany::Many(vec![1, 2]).into_iter().collect();
        assert_eq!(v, vec![1, 2]);
    }

    // --- OneOrMany: non-consuming iterator ---

    #[test]
    fn ref_into_iter_one() {
        let v = OneOrMany::One(42);
        let refs: Vec<&i32> = (&v).into_iter().collect();
        assert_eq!(refs, vec![&42]);
    }

    #[test]
    fn ref_into_iter_many() {
        let v = OneOrMany::Many(vec![1, 2]);
        let refs: Vec<&i32> = (&v).into_iter().collect();
        assert_eq!(refs, vec![&1, &2]);
    }

    // --- OneOrMany: serde ---

    #[test]
    fn serde_one_roundtrip() {
        let v = OneOrMany::One("hello".to_string());
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, r#""hello""#);
        let back: OneOrMany<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn serde_many_roundtrip() {
        let v = OneOrMany::Many(vec!["a".to_string(), "b".to_string()]);
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, r#"["a","b"]"#);
        let back: OneOrMany<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    // --- OneOrManyRef ---

    #[test]
    fn from_slice_single() {
        let data = [42];
        let r = OneOrManyRef::from_slice(&data);
        assert!(matches!(r, OneOrManyRef::One(&42)));
    }

    #[test]
    fn from_slice_multiple() {
        let data = [1, 2, 3];
        let r = OneOrManyRef::from_slice(&data);
        assert!(matches!(r, OneOrManyRef::Many(&[1, 2, 3])));
    }

    #[test]
    fn from_slice_empty() {
        let data: [i32; 0] = [];
        let r = OneOrManyRef::from_slice(&data);
        assert!(matches!(r, OneOrManyRef::Many(&[])));
    }

    #[test]
    fn one_or_many_ref_is_empty() {
        let data: [i32; 0] = [];
        assert!(OneOrManyRef::from_slice(&data).is_empty());
        assert!(!OneOrManyRef::from_slice(&[1]).is_empty());
        assert!(!OneOrManyRef::from_slice(&[1, 2]).is_empty());
    }
}
