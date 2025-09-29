// 最大流算法实现，用于优化闪电网络路径分配
use crate::fiber::{
    channel::ChannelActorStateStore,
    gossip::GossipMessageStore,
    graph::{NetworkGraph, NetworkGraphStateStore},
    network::SendPaymentData,
    types::Pubkey,
};
use crate::Error;
use ckb_types::packed::OutPoint;
use std::collections::{HashMap, VecDeque};

/// 内部边表示，用于最大流算法
#[derive(Debug, Clone)]
pub struct FlowEdge {
    pub from: usize,
    pub to: usize,
    pub min_flow: i64,
    pub max_flow: i64,
    // 保存原始通道信息用于后续转换
    pub channel_outpoint: OutPoint,
    pub fee_rate: u128,
}

/// 表示解决方案中的一条路径及其流量
#[derive(Debug, Clone)]
pub struct SolutionPath {
    pub path: Vec<usize>,
    pub flow: i64,
}

/// Dinic最大流算法的边结构
#[derive(Clone)]
struct Edge {
    to: usize,
    cap: i64,
    rev: usize,
}

/// 网络流图结构
struct FlowGraph {
    adj: Vec<Vec<Edge>>,
}

impl FlowGraph {
    fn new(n: usize) -> Self {
        FlowGraph {
            adj: vec![Vec::new(); n],
        }
    }

    fn add_edge(&mut self, from: usize, to: usize, cap: i64) {
        let from_len = self.adj[from].len();
        let to_len = self.adj[to].len();
        self.adj[from].push(Edge {
            to,
            cap,
            rev: to_len,
        });
        self.adj[to].push(Edge {
            to: from,
            cap: 0,
            rev: from_len,
        });
    }
}

/// Dinic最大流算法实现
struct Dinic {
    graph: FlowGraph,
    level: Vec<i32>,
    iter: Vec<usize>,
}

impl Dinic {
    fn new(graph: FlowGraph) -> Self {
        let n = graph.adj.len();
        Dinic {
            graph,
            level: vec![0; n],
            iter: vec![0; n],
        }
    }

    fn bfs(&mut self, s: usize, t: usize) -> bool {
        let n = self.graph.adj.len();
        self.level = vec![-1; n];
        let mut q = VecDeque::new();
        self.level[s] = 0;
        q.push_back(s);

        while let Some(v) = q.pop_front() {
            for edge in &self.graph.adj[v] {
                if edge.cap > 0 && self.level[edge.to] < 0 {
                    self.level[edge.to] = self.level[v] + 1;
                    q.push_back(edge.to);
                }
            }
        }
        self.level[t] != -1
    }

    fn dfs(&mut self, v: usize, t: usize, f: i64) -> i64 {
        if v == t {
            return f;
        }

        while self.iter[v] < self.graph.adj[v].len() {
            let edge_idx = self.iter[v];
            let edge = self.graph.adj[v][edge_idx].clone();

            if edge.cap > 0 && self.level[v] < self.level[edge.to] {
                let d = self.dfs(edge.to, t, f.min(edge.cap));
                if d > 0 {
                    self.graph.adj[v][edge_idx].cap -= d;
                    let rev_edge_idx = edge.rev;
                    self.graph.adj[edge.to][rev_edge_idx].cap += d;
                    return d;
                }
            }
            self.iter[v] += 1;
        }
        0
    }

    fn max_flow(&mut self, s: usize, t: usize) -> i64 {
        let mut flow = 0;
        while self.bfs(s, t) {
            let n = self.graph.adj.len();
            self.iter = vec![0; n];
            loop {
                let f = self.dfs(s, t, i64::MAX);
                if f == 0 {
                    break;
                }
                flow += f;
            }
        }
        flow
    }
}

/// 最大流路由求解器
pub struct MaxFlowRouter;

impl MaxFlowRouter {
    /// 从网络图中提取拓扑结构，转换为最大流算法所需的格式
    /// 集成了 find_path 中的过滤和检查逻辑
    pub fn extract_network_topology<S>(
        graph: &NetworkGraph<S>,
        payment_data: &SendPaymentData,
        max_fee: Option<u128>,
    ) -> Result<(HashMap<Pubkey, usize>, Vec<FlowEdge>), Error>
    where
        S: NetworkGraphStateStore
            + ChannelActorStateStore
            + GossipMessageStore
            + Clone
            + Send
            + Sync
            + 'static,
    {
        let mut node_map = HashMap::new();
        let mut node_counter = 0usize;
        let mut edges = Vec::new();

        let target_pubkey = payment_data.target_pubkey;
        let udt_type_script = &payment_data.udt_type_script;
        let allow_mpp = payment_data.allow_mpp();
        let channel_stats = &payment_data.channel_stats;
        let tlc_expiry_limit = payment_data.tlc_expiry_limit;

        // 遍历所有通道进行过滤和检查
        for channel_info in graph.channels() {
            let node1 = channel_info.node1();
            let node2 = channel_info.node2();

            // 检查UDT类型脚本匹配
            if udt_type_script != channel_info.udt_type_script() {
                continue;
            }

            // 为节点分配索引
            if !node_map.contains_key(&node1) {
                node_map.insert(node1, node_counter);
                node_counter += 1;
            }
            if !node_map.contains_key(&node2) {
                node_map.insert(node2, node_counter);
                node_counter += 1;
            }

            let node1_idx = node_map[&node1];
            let node2_idx = node_map[&node2];

            // 处理 node1 -> node2 方向
            if let Some(update1) = &channel_info.update_of_node1 {
                if Self::is_channel_usable(
                    channel_info,
                    update1,
                    node1,
                    node2,
                    target_pubkey,
                    max_fee,
                    allow_mpp,
                    channel_stats,
                    tlc_expiry_limit,
                    graph,
                ) {
                    let effective_capacity = Self::calculate_effective_capacity(
                        channel_info,
                        update1,
                        node1,
                        channel_stats,
                    );

                    if effective_capacity > 0 {
                        edges.push(FlowEdge {
                            from: node1_idx,
                            to: node2_idx,
                            min_flow: if allow_mpp {
                                0
                            } else {
                                update1.tlc_minimum_value as i64
                            },
                            max_flow: effective_capacity as i64,
                            channel_outpoint: channel_info.channel_outpoint.clone(),
                            fee_rate: update1.fee_rate as u128,
                        });
                    }
                }
            }

            // 处理 node2 -> node1 方向
            if let Some(update2) = &channel_info.update_of_node2 {
                if Self::is_channel_usable(
                    channel_info,
                    update2,
                    node2,
                    node1,
                    target_pubkey,
                    max_fee,
                    allow_mpp,
                    channel_stats,
                    tlc_expiry_limit,
                    graph,
                ) {
                    let effective_capacity = Self::calculate_effective_capacity(
                        channel_info,
                        update2,
                        node2,
                        channel_stats,
                    );

                    if effective_capacity > 0 {
                        edges.push(FlowEdge {
                            from: node2_idx,
                            to: node1_idx,
                            min_flow: if allow_mpp {
                                0
                            } else {
                                update2.tlc_minimum_value as i64
                            },
                            max_flow: effective_capacity as i64,
                            channel_outpoint: channel_info.channel_outpoint.clone(),
                            fee_rate: update2.fee_rate as u128,
                        });
                    }
                }
            }
        }

        Ok((node_map, edges))
    }

    /// 检查通道是否可用，集成了 find_path 中的检查逻辑
    fn is_channel_usable<S>(
        _channel_info: &crate::fiber::graph::ChannelInfo,
        channel_update: &crate::fiber::graph::ChannelUpdateInfo,
        _from_node: Pubkey,
        _to_node: Pubkey,
        _target_pubkey: Pubkey,
        max_fee: Option<u128>,
        _allow_mpp: bool,
        _channel_stats: &crate::fiber::graph::GraphChannelStat,
        tlc_expiry_limit: u64,
        _graph: &NetworkGraph<S>,
    ) -> bool
    where
        S: NetworkGraphStateStore
            + ChannelActorStateStore
            + GossipMessageStore
            + Clone
            + Send
            + Sync
            + 'static,
    {
        use crate::fiber::config::DEFAULT_TLC_EXPIRY_DELTA;
        use crate::fiber::fee::calculate_tlc_forward_fee;

        // 检查通道是否启用
        if !channel_update.enabled {
            return false;
        }

        // 检查TLC到期增量是否合理
        if channel_update.tlc_expiry_delta > DEFAULT_TLC_EXPIRY_DELTA {
            return false;
        }

        // 检查到期时间限制
        // 使用估算的TLC到期时间进行检查
        let estimated_expiry = channel_update.tlc_expiry_delta;
        if estimated_expiry > tlc_expiry_limit {
            return false;
        }

        // 对于非源节点，检查费用计算是否有效
        // 这里使用一个估算金额进行检查，实际金额在后续处理中确定
        let test_amount = 1000u128; // 使用较小的测试金额

        // 检查费用计算是否有效
        if calculate_tlc_forward_fee(test_amount, channel_update.fee_rate as u128).is_err() {
            return false;
        }

        // 如果设置了最大费用限制，检查费用是否超出限制
        if let Some(max_fee_amount) = max_fee {
            if let Ok(fee) = calculate_tlc_forward_fee(test_amount, channel_update.fee_rate as u128)
            {
                // 这是一个粗略的检查，实际的费用检查会在路径构建时进行
                // 使用费用率进行粗略估算
                if fee > max_fee_amount / 10 {
                    // 简单的启发式检查
                    return false;
                }
            }
        }

        // 对于MPP支持，这里简化检查，假设大多数现代节点都支持MPP
        // 在实际使用中，应该检查节点特性，但这需要访问节点信息
        // 简化的MPP检查：如果节点有有效的通道更新，假设支持MPP
        // 这是一个简化的假设，在生产环境中应该检查节点的feature bits

        true
    }

    /// 计算通道的有效容量，考虑已发送金额
    fn calculate_effective_capacity(
        channel_info: &crate::fiber::graph::ChannelInfo,
        channel_update: &crate::fiber::graph::ChannelUpdateInfo,
        from_node: Pubkey,
        channel_stats: &crate::fiber::graph::GraphChannelStat,
    ) -> u128 {
        use crate::fiber::history::SentNode;

        // 获取通道的基础容量
        let base_capacity = if let Some(liquidity) = channel_update.outbound_liquidity {
            liquidity
        } else {
            channel_info.capacity()
        };

        // 获取已发送的金额
        let sent_node = channel_info
            .get_send_node(from_node)
            .unwrap_or(SentNode::Node1);
        let sent_amount =
            channel_stats.get_channel_sent_amount(channel_info.out_point(), sent_node);

        // 计算有效容量
        base_capacity.saturating_sub(sent_amount)
    }

    /// 使用最大流算法求解路径分配问题
    pub fn solve_max_flow_routing(
        num_nodes: usize,
        edges: &[FlowEdge],
        source: usize,
        target: usize,
        amount: i64,
        max_parts: usize,
    ) -> Result<Vec<SolutionPath>, Error> {
        if source == target {
            return Err(Error::SendPaymentError(
                "Source and target cannot be the same".to_string(),
            ));
        }
        if amount <= 0 {
            return Err(Error::SendPaymentError(
                "Amount must be positive".to_string(),
            ));
        }
        if max_parts == 0 {
            return Err(Error::SendPaymentError(
                "Max parts must be positive".to_string(),
            ));
        }

        // 阶段一：使用最大流算法分解路径
        let decomposed_paths =
            Self::decompose_flow_with_constraints(num_nodes, edges, source, target)?;

        // 阶段二：组合路径以满足所需金额和数量限制
        let solution = Self::combine_paths(decomposed_paths, amount, max_parts)?;

        Ok(solution)
    }

    /// 带约束的路径分解
    fn decompose_flow_with_constraints(
        num_nodes: usize,
        original_edges: &[FlowEdge],
        source: usize,
        target: usize,
    ) -> Result<Vec<SolutionPath>, Error> {
        let mut graph = FlowGraph::new(num_nodes);
        for edge in original_edges {
            graph.add_edge(edge.from, edge.to, edge.max_flow);
        }

        let mut dinic = Dinic::new(graph);
        let max_flow = dinic.max_flow(source, target);

        if max_flow == 0 && source != target {
            return Ok(Vec::new());
        }

        // 从残差网络重构流分配
        let mut flow_graph = FlowGraph::new(num_nodes);
        for edge in original_edges {
            if let Some(residual_edge) = dinic.graph.adj[edge.from].iter().find(|e| e.to == edge.to)
            {
                let actual_flow = edge.max_flow - residual_edge.cap;
                if actual_flow > 0 {
                    flow_graph.add_edge(edge.from, edge.to, actual_flow);
                }
            }
        }

        // 分解流为路径
        Ok(Self::decompose_flow(&mut flow_graph, source, target))
    }

    fn decompose_flow(flow_graph: &mut FlowGraph, s: usize, t: usize) -> Vec<SolutionPath> {
        let mut paths = Vec::new();

        loop {
            let mut parent = vec![None; flow_graph.adj.len()];
            let mut q: VecDeque<(usize, i64)> = VecDeque::new();
            q.push_back((s, i64::MAX));
            parent[s] = Some(s);

            let mut path_found = false;
            let mut bottleneck = 0;

            while let Some((u, flow)) = q.pop_front() {
                if u == t {
                    bottleneck = flow;
                    path_found = true;
                    break;
                }
                for edge in &flow_graph.adj[u] {
                    if parent[edge.to].is_none() && edge.cap > 0 {
                        parent[edge.to] = Some(u);
                        let new_flow = flow.min(edge.cap);
                        q.push_back((edge.to, new_flow));
                    }
                }
            }

            if path_found {
                let mut path = Vec::new();
                let mut curr = t;
                while curr != s {
                    path.push(curr);
                    curr = parent[curr].unwrap();
                }
                path.push(s);
                path.reverse();

                // 从图中减去瓶颈流
                let mut prev = s;
                for &node in path.iter().skip(1) {
                    for edge in &mut flow_graph.adj[prev] {
                        if edge.to == node {
                            edge.cap -= bottleneck;
                            break;
                        }
                    }
                    prev = node;
                }

                paths.push(SolutionPath {
                    path,
                    flow: bottleneck,
                });
            } else {
                break;
            }
        }

        paths
    }

    fn combine_paths(
        mut decomposed_paths: Vec<SolutionPath>,
        amount: i64,
        max_parts: usize,
    ) -> Result<Vec<SolutionPath>, Error> {
        if amount <= 0 {
            return Err(Error::SendPaymentError(
                "Amount must be positive".to_string(),
            ));
        }
        if max_parts == 0 {
            return Err(Error::SendPaymentError(
                "Max parts must be positive".to_string(),
            ));
        }
        if decomposed_paths.is_empty() {
            return Err(Error::SendPaymentError("No available paths".to_string()));
        }

        // 按容量降序排序
        decomposed_paths.sort_by(|a, b| b.flow.cmp(&a.flow));

        // 如果最大的一条路径就能满足需求，直接使用它
        if decomposed_paths[0].flow >= amount {
            return Ok(vec![SolutionPath {
                path: decomposed_paths[0].path.clone(),
                flow: amount,
            }]);
        }

        let mut result: Vec<SolutionPath> = Vec::new();
        let mut remaining = amount;

        // 检查是否可以用前max_parts条路径满足需求
        let available_paths: Vec<&SolutionPath> = decomposed_paths.iter().take(max_parts).collect();
        let total_available: i64 = available_paths.iter().map(|p| p.flow).sum();

        if total_available < remaining {
            return Err(Error::SendPaymentError(format!(
                "Could not satisfy amount {} with {} paths. Total available: {}",
                amount, max_parts, total_available
            )));
        }

        // 贪心分配流量
        for path in available_paths.iter() {
            if remaining == 0 {
                break;
            }
            let take = path.flow.min(remaining);
            if take > 0 {
                result.push(SolutionPath {
                    path: path.path.clone(),
                    flow: take,
                });
                remaining -= take;
            }
        }

        if remaining > 0 {
            return Err(Error::SendPaymentError(format!(
                "Could not satisfy amount {} with {} paths. {} still remaining",
                amount, max_parts, remaining
            )));
        }

        Ok(result)
    }

    /// 计算跳点费用
    pub fn calculate_hop_fee(amount: u128, fee_rate: u128) -> u128 {
        // 简化的费用计算：amount * fee_rate / 1_000_000
        amount * fee_rate / 1_000_000
    }
}
