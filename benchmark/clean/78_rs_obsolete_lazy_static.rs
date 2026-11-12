use std::sync::LazyLock;
static REGISTRY: LazyLock<Vec<String>> = LazyLock::new(Vec::new);
