use super::rlp::RlpNode;

pub(super) trait Memoization: Default {
    fn clear(&mut self);
    fn get(&self) -> Option<&RlpNode>;
    fn set(&mut self, rlp_node: RlpNode);
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct NoCache;

impl Memoization for NoCache {
    #[inline]
    fn clear(&mut self) {}
    #[inline]
    fn get(&self) -> Option<&RlpNode> {
        None
    }
    #[inline]
    fn set(&mut self, _: RlpNode) {}
}

#[derive(Debug, Clone, Default)]
pub(super) struct Cache(Option<RlpNode>);

impl Memoization for Cache {
    #[inline]
    fn clear(&mut self) {
        self.0 = None
    }
    #[inline]
    fn get(&self) -> Option<&RlpNode> {
        self.0.as_ref()
    }
    #[inline]
    fn set(&mut self, rlp_node: RlpNode) {
        self.0 = Some(rlp_node)
    }
}
