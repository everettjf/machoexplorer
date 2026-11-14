//! Scroll math for uniformly sized rows. Positions are `f64` so tens of
//! millions of rows keep sub-pixel precision; only the visible rows are ever
//! materialised by the views built on this.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollTo {
    /// Scroll the minimum amount needed to make the row fully visible.
    Nearest,
    Center,
    Top,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VScroll {
    pub total_rows: u64,
    pub row_height: f32,
    pub viewport: f32,
    /// Distance in pixels from the top of row 0 to the top of the viewport.
    pub top: f64,
}

/// Rows to draw: `count` rows starting at `first`, the first one positioned
/// at `y` (<= 0) relative to the viewport top.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VisibleRows {
    pub first: u64,
    pub count: usize,
    pub y: f32,
}

pub const MIN_THUMB: f32 = 24.0;

impl VScroll {
    pub fn new(row_height: f32) -> Self {
        VScroll {
            total_rows: 0,
            row_height,
            viewport: 0.0,
            top: 0.0,
        }
    }

    pub fn content_height(&self) -> f64 {
        self.total_rows as f64 * self.row_height as f64
    }

    pub fn max_top(&self) -> f64 {
        (self.content_height() - self.viewport as f64).max(0.0)
    }

    pub fn clamp(&mut self) {
        self.top = self.top.clamp(0.0, self.max_top());
    }

    pub fn set_total(&mut self, total_rows: u64) {
        self.total_rows = total_rows;
        self.clamp();
    }

    /// Returns true when the size actually changed.
    pub fn set_viewport(&mut self, viewport: f32) -> bool {
        if (self.viewport - viewport).abs() < 0.5 {
            return false;
        }
        self.viewport = viewport;
        self.clamp();
        true
    }

    /// Scroll by `dy` pixels (positive = towards the end). True if moved.
    pub fn scroll_by(&mut self, dy: f64) -> bool {
        let before = self.top;
        self.top += dy;
        self.clamp();
        self.top != before
    }

    pub fn scroll_to_top(&mut self) {
        self.top = 0.0;
    }

    pub fn page_rows(&self) -> u64 {
        ((self.viewport / self.row_height).floor() as u64).max(1)
    }

    pub fn visible(&self) -> VisibleRows {
        if self.total_rows == 0 || self.viewport <= 0.0 || self.row_height <= 0.0 {
            return VisibleRows {
                first: 0,
                count: 0,
                y: 0.0,
            };
        }
        let rh = self.row_height as f64;
        let first = ((self.top / rh).floor() as u64).min(self.total_rows - 1);
        let y = (first as f64 * rh - self.top) as f32;
        let needed = ((self.viewport - y) / self.row_height).ceil().max(0.0) as u64;
        let count = needed.min(self.total_rows - first) as usize;
        VisibleRows { first, count, y }
    }

    pub fn ensure_visible(&mut self, row: u64, how: ScrollTo) {
        if self.total_rows == 0 {
            return;
        }
        let rh = self.row_height as f64;
        let row = row.min(self.total_rows - 1);
        let row_top = row as f64 * rh;
        let row_bottom = row_top + rh;
        let vp = self.viewport as f64;
        match how {
            ScrollTo::Top => self.top = row_top,
            ScrollTo::Center => self.top = row_top - (vp - rh) / 2.0,
            ScrollTo::Nearest => {
                if row_top < self.top {
                    self.top = row_top;
                } else if row_bottom > self.top + vp {
                    // Never scroll the row's top out of view (tiny or not
                    // yet measured viewports).
                    self.top = (row_bottom - vp).min(row_top);
                }
            }
        }
        self.clamp();
    }

    /// True if any part of `row` is inside the viewport.
    pub fn is_row_visible(&self, row: u64) -> bool {
        let rh = self.row_height as f64;
        let t = row as f64 * rh;
        t + rh > self.top && t < self.top + self.viewport as f64
    }

    /// Scrollbar thumb `(start, length)` within a track of `track` pixels,
    /// or `None` when everything fits.
    pub fn thumb(&self, track: f32) -> Option<(f32, f32)> {
        let content = self.content_height();
        if content <= self.viewport as f64 || track <= 0.0 {
            return None;
        }
        let len = ((self.viewport as f64 / content) * track as f64)
            .max(MIN_THUMB as f64)
            .min(track as f64);
        let travel = track as f64 - len;
        let start = if self.max_top() > 0.0 {
            self.top / self.max_top() * travel
        } else {
            0.0
        };
        Some((start as f32, len as f32))
    }

    /// Inverse of [`thumb`]: place the thumb's start at `thumb_start`.
    pub fn set_thumb_start(&mut self, track: f32, thumb_start: f32) {
        let Some((_, len)) = self.thumb(track) else {
            return;
        };
        let travel = (track - len).max(1.0) as f64;
        self.top = (thumb_start as f64 / travel).clamp(0.0, 1.0) * self.max_top();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vs(total: u64, viewport: f32) -> VScroll {
        VScroll {
            total_rows: total,
            row_height: 20.0,
            viewport,
            top: 0.0,
        }
    }

    #[test]
    fn visible_rows_are_bounded_by_viewport() {
        let mut s = vs(500_000, 400.0);
        assert_eq!(
            s.visible(),
            VisibleRows {
                first: 0,
                count: 20,
                y: 0.0
            }
        );
        s.scroll_by(30.0);
        assert_eq!(
            s.visible(),
            VisibleRows {
                first: 1,
                count: 21,
                y: -10.0
            }
        );
        s.scroll_by(1e12);
        let v = s.visible();
        assert_eq!(v.first + v.count as u64, 500_000);
        assert_eq!(v.count, 20);
    }

    #[test]
    fn short_content_and_empty() {
        assert_eq!(vs(3, 400.0).visible().count, 3);
        assert_eq!(vs(0, 400.0).visible().count, 0);
        assert_eq!(vs(10, 0.0).visible().count, 0);
        let mut s = vs(3, 400.0);
        assert!(!s.scroll_by(100.0));
        assert_eq!(s.thumb(400.0), None);
    }

    #[test]
    fn huge_row_counts_keep_precision() {
        // 4 GiB of hex rows.
        let mut s = vs((4u64 << 30) / 16, 600.0);
        s.ensure_visible(200_000_001, ScrollTo::Top);
        let v = s.visible();
        assert_eq!(v.first, 200_000_001);
        assert_eq!(v.y, 0.0);
        assert_eq!(v.count, 30);
        s.scroll_by(7.0);
        assert_eq!(s.visible().y, -7.0);
    }

    #[test]
    fn ensure_visible_strategies() {
        let mut s = vs(1000, 200.0);
        s.ensure_visible(5, ScrollTo::Nearest);
        assert_eq!(s.top, 0.0);
        s.ensure_visible(10, ScrollTo::Nearest);
        assert_eq!(s.top, 20.0);
        s.ensure_visible(500, ScrollTo::Center);
        assert_eq!(s.top, 500.0 * 20.0 - 90.0);
        assert!(s.is_row_visible(500));
        s.ensure_visible(999, ScrollTo::Top);
        assert_eq!(s.top, s.max_top());
        s.ensure_visible(0, ScrollTo::Nearest);
        assert_eq!(s.top, 0.0);
        // Before the first layout the viewport is unknown (0): stay put.
        let mut unmeasured = vs(1000, 0.0);
        unmeasured.ensure_visible(0, ScrollTo::Nearest);
        assert_eq!(unmeasured.top, 0.0);
        unmeasured.ensure_visible(7, ScrollTo::Nearest);
        assert_eq!(unmeasured.top, 140.0);
    }

    #[test]
    fn thumb_round_trip() {
        let mut s = vs(10_000, 500.0);
        let (start, len) = s.thumb(500.0).unwrap();
        assert_eq!(start, 0.0);
        assert_eq!(len, MIN_THUMB);
        s.set_thumb_start(500.0, 238.0);
        let (start, _) = s.thumb(500.0).unwrap();
        assert!((start - 238.0).abs() < 0.01);
        s.set_thumb_start(500.0, 1e6);
        assert_eq!(s.top, s.max_top());
    }

    #[test]
    fn viewport_changes_clamp() {
        let mut s = vs(100, 200.0);
        s.scroll_by(1e9);
        assert_eq!(s.top, 1800.0);
        assert!(s.set_viewport(1000.0));
        assert_eq!(s.top, 1000.0);
        assert!(!s.set_viewport(1000.2));
        assert_eq!(s.page_rows(), 50);
    }
}
