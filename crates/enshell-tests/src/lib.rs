//! Cross-cutting integration, golden, property, and fuzz test harnesses and fixtures.

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(2 + 2, 4);
    }
}
