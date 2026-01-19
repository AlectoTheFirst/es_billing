# Elasticsearch Index Impact Analyzer for Billing

A Python tool that analyzes the heap and storage impact of Elasticsearch indices to derive fair, impact-based billing for multi-tenant clusters.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic usage (local ES)

```bash
python es_index_impact_analyzer.py
```

### With authentication

```bash
python es_index_impact_analyzer.py \
    --host es.example.com \
    --port 9200 \
    --user elastic \
    --password mypassword \
    --ssl
```

Use `--insecure` to skip TLS verification if your cluster uses self-signed certs.

### Output as JSON

```bash
python es_index_impact_analyzer.py --json
python es_index_impact_analyzer.py --json -o billing_report.json
```

### Customize weights

```bash
python es_index_impact_analyzer.py \
    --score-mode weighted \
    --weight-storage 2.0 \
    --weight-shards 10.0 \
    --weight-fielddata 5.0
```

### Show only top consumers

```bash
python es_index_impact_analyzer.py --top 10
```

## Index Naming Convention

By default, this tool expects indices to follow this pattern:

```
logstash-{logname}-{rollover_number}
```

Examples:
- `logstash-nginx-access-000001`
- `logstash-application-errors-000042`
- `logstash-security-audit-000007`

Indices are grouped by `{logname}` and metrics are aggregated across all rolled indices.
You can override the regex with `--index-pattern`.

## Scoring Modes

### Normalized (default)

The default mode is capacity-based: each group is scored against cluster totals.

```
impact_score = (total_storage_gb / cluster_disk_total_gb) +
               (heap_usage_mb / cluster_heap_max_mb)

heap_usage_mb = segment_memory_mb + fielddata_mb + query_cache_mb + request_cache_mb
```

Cluster totals are pulled from `/_cluster/stats` and represent the provisioned
capacity of the cluster.

### Weighted (opt-in)

Use an explicit weighted formula when you want to tune costs manually:

```
impact_score = (storage_gb × W1) + (shard_count × W2) + (segment_count × W3) + (fielddata_mb × W4) + (query_cache_mb × W5)
```

Enable with `--score-mode weighted` and adjust weights as needed.
`storage_gb` uses total storage (primaries + replicas).

### Default Weights (weighted mode)

| Metric | Default Weight | Rationale |
|--------|---------------|-----------|
| `storage_gb` | 1.0 | Direct disk cost |
| `shard_count` | 5.0 | Each shard consumes ~10-50MB heap overhead |
| `segment_count` | 0.1 | Merge overhead, minor impact |
| `fielddata_mb` | 2.0 | Direct heap consumption for aggregations |
| `query_cache_mb` | 0.5 | Shared cache, lower weight |

### Tuning Weights for Your Cluster

**Heap-constrained clusters:** Increase weights for `shard_count` and `fielddata_mb`

```bash
--score-mode weighted --weight-shards 15.0 --weight-fielddata 5.0
```

**Storage-constrained clusters:** Increase `storage_gb` weight

```bash
--score-mode weighted --weight-storage 3.0
```

**High query load:** Consider adding request rate metrics (requires modification)

## Metrics Collected

For each index:

| Metric | Source API | Description |
|--------|------------|-------------|
| Primary store size | `/_stats` | Disk usage (primary shards only) |
| Total store size | `/_stats` | Disk usage including replicas (used for capacity scoring) |
| Document count | `/_stats` | Number of documents |
| Shard count | `/_settings` | Primary × (1 + replicas) |
| Segment count | `/_stats` | Number of Lucene segments |
| Segment memory | `/_stats` | Heap used by segment metadata |
| Fielddata memory | `/_stats` | Heap used for fielddata cache |
| Query cache memory | `/_stats` | Heap used for query cache |
| Request cache memory | `/_stats` | Heap used for request cache |

## Sample Output

```
================================================================================
ELASTICSEARCH INDEX IMPACT ANALYSIS FOR BILLING
================================================================================

Scoring mode: normalized (cluster capacity)
Cluster totals: disk 10240.00G, heap 65536MB

Total log groups analyzed: 15
Total impact score: 5.00
Storage column uses total store size (primaries + replicas).

--------------------------------------------------------------------------------
Log Name                                     Impact    Storage   Shards  Indices
--------------------------------------------------------------------------------
nginx-access                                   1.84     45.23G       30        5
application-logs                               1.17     28.11G       24        4
security-audit                                 0.53     12.45G       12        2
...

================================================================================
BILLING PERCENTAGE BREAKDOWN
================================================================================

Log Name                                     Impact %   Estimated Monthly $
--------------------------------------------------------------------------------
nginx-access                                   36.88%            $368.78
application-logs                               23.41%            $234.09
security-audit                                 10.53%            $105.29
...
(Based on example cluster cost of $1000/month)
```

## JSON Output Schema

```json
[
  {
    "log_name": "nginx-access",
    "index_count": 5,
    "impact_score": 312.45,
    "metrics": {
      "primary_storage_gb": 45.234,
      "total_storage_gb": 90.468,
      "doc_count": 1234567890,
      "total_shards": 30,
      "total_segments": 150,
      "segment_memory_mb": 45.23,
      "fielddata_mb": 12.34,
      "query_cache_mb": 5.67,
      "request_cache_mb": 2.34
    },
    "indices": [
      "logstash-nginx-access-000001",
      "logstash-nginx-access-000002",
      "..."
    ]
  }
]
```

## Extending the Analyzer

### Adding Query/Indexing Rate Metrics

To capture operational impact, you can extend the analyzer to include:

```python
# Add to collect_metrics():
# Get index-level search/indexing stats
search_stats = self.es.indices.stats(metric=['search', 'indexing'])

# Extract rates
search_rate = primaries.get('search', {}).get('query_total', 0)
index_rate = primaries.get('indexing', {}).get('index_total', 0)
```

### Custom Index Pattern

Provide a custom regex at runtime:

```bash
# For pattern: myapp-{env}-{logname}-{date}
python es_index_impact_analyzer.py \\
    --index-pattern '^myapp-\\w+-(?P<log_name>.+)-\\d{4}\\.\\d{2}\\.\\d{2}$'
```

## License

MIT# es_billing
Simple Tool to facilitate ES billing
