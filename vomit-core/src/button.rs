//! Classifies presses of the single "insert" button by how long they were held.
//!
//! * tap            -> insert the selected value
//! * hold           -> insert the selected value and submit ("116 hold insert")
//! * very long hold -> clear everything

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Press {
    Short,
    Long,
    VeryLong,
}

#[derive(Clone, Copy, Debug)]
pub struct PressTiming {
    /// Presses shorter than this are treated as contact bounce and ignored.
    pub debounce_ms: u32,
    pub long_ms: u32,
    pub very_long_ms: u32,
}

impl Default for PressTiming {
    fn default() -> Self {
        Self { debounce_ms: 30, long_ms: 700, very_long_ms: 3000 }
    }
}

impl PressTiming {
    /// Classify a completed press. `None` means bounce.
    pub fn classify(&self, held_ms: u32) -> Option<Press> {
        if held_ms < self.debounce_ms {
            None
        } else if held_ms < self.long_ms {
            Some(Press::Short)
        } else if held_ms < self.very_long_ms {
            Some(Press::Long)
        } else {
            Some(Press::VeryLong)
        }
    }

    /// What releasing the button *now* would do, for live feedback on the
    /// display while it's still held.
    pub fn pending(&self, held_ms: u32) -> Option<Press> {
        self.classify(held_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify() {
        let t = PressTiming::default();
        assert_eq!(t.classify(5), None);
        assert_eq!(t.classify(100), Some(Press::Short));
        assert_eq!(t.classify(1000), Some(Press::Long));
        assert_eq!(t.classify(5000), Some(Press::VeryLong));
    }
}
