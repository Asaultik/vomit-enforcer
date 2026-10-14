//! Maps a noisy 12-bit reading (potentiometer, analog hall sensor, AS5600
//! analog out, ...) onto `steps` discrete values with hysteresis, so the
//! selected value doesn't flicker when the dial sits on a bucket boundary.

/// Full scale of the ADC reading fed into [`DialQuantizer::update`].
pub const ADC_MAX: u16 = 4095;

pub struct DialQuantizer {
    steps: u16,
    /// Hysteresis in raw ADC counts. A new bucket is only accepted once the
    /// reading is this far past the boundary of the current bucket.
    hysteresis: u16,
    /// Exponential moving average of the raw reading, scaled by 16.
    avg_x16: Option<u32>,
    current: Option<u16>,
    invert: bool,
}

impl DialQuantizer {
    pub fn new(steps: u16, hysteresis: u16) -> Self {
        assert!(steps >= 2 && steps as u32 <= ADC_MAX as u32 + 1);
        Self { steps, hysteresis, avg_x16: None, current: None, invert: false }
    }

    /// Flip the direction of the dial, for when it was wired backwards.
    pub fn inverted(mut self, invert: bool) -> Self {
        self.invert = invert;
        self
    }

    pub fn steps(&self) -> u16 {
        self.steps
    }

    pub fn value(&self) -> Option<u16> {
        self.current
    }

    /// Bucket width in raw counts, as a fraction: bucket `b` covers
    /// `[b * span / steps, (b + 1) * span / steps)`.
    fn lower_edge(&self, bucket: u16) -> u32 {
        bucket as u32 * (ADC_MAX as u32 + 1) / self.steps as u32
    }

    fn bucket_of(&self, raw: u32) -> u16 {
        ((raw * self.steps as u32) / (ADC_MAX as u32 + 1)) as u16
    }

    /// Feed one raw sample. Returns `Some(value)` when the selected value
    /// changed.
    pub fn update(&mut self, raw: u16) -> Option<u16> {
        let raw = raw.min(ADC_MAX) as u32;
        let raw = if self.invert { ADC_MAX as u32 - raw } else { raw };

        // Light low-pass: avg += (raw - avg) / 4
        let avg_x16 = match self.avg_x16 {
            None => raw * 16,
            Some(a) => (a * 3 + raw * 16) / 4,
        };
        self.avg_x16 = Some(avg_x16);
        let smoothed = avg_x16 / 16;

        let candidate = self.bucket_of(smoothed);
        let accept = match self.current {
            None => true,
            Some(cur) if candidate == cur => false,
            Some(cur) => {
                let lo = self.lower_edge(cur);
                let hi = self.lower_edge(cur + 1);
                let h = self.hysteresis as u32;
                smoothed + h < lo || smoothed >= hi + h
            }
        };
        if accept {
            self.current = Some(candidate);
            Some(candidate)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settle(q: &mut DialQuantizer, raw: u16) -> Option<u16> {
        for _ in 0..32 {
            q.update(raw);
        }
        q.value()
    }

    #[test]
    fn covers_full_range() {
        let mut q = DialQuantizer::new(128, 8);
        assert_eq!(settle(&mut q, 0), Some(0));
        assert_eq!(settle(&mut q, 4095), Some(127));
        assert_eq!(settle(&mut q, 2048), Some(64));
    }

    #[test]
    fn hysteresis_holds_on_boundary() {
        let mut q = DialQuantizer::new(128, 8);
        // Bucket 10 is [320, 352).
        assert_eq!(settle(&mut q, 330), Some(10));
        // Jitter just over the upper edge doesn't switch.
        assert_eq!(settle(&mut q, 355), Some(10));
        assert_eq!(settle(&mut q, 318), Some(10));
        // Clearly past it does.
        assert_eq!(settle(&mut q, 365), Some(11));
    }

    #[test]
    fn inverted() {
        let mut q = DialQuantizer::new(128, 8).inverted(true);
        assert_eq!(settle(&mut q, 0), Some(127));
    }
}
