from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class SimulationRequest(BaseModel):
    blocked_techniques: List[str] = Field(
        ...,
        description="Daftar Technique ID MITRE ATT&CK (misal: T1059.001) yang disimulasikan untuk dicegah.",
        example=["T1059.001", "T1003.001"],
    )


class OptimizedControl(BaseModel):
    control_name: str = Field(
        ..., description="Nama kontrol mitigasi, contoh: 'Email Gateway Filtering'"
    )
    risk_reduction_score: int = Field(
        ...,
        description="Nilai absolut penurunan skor risiko yang disumbangkan oleh kontrol ini",
    )
    risk_reduction_percentage: str = Field(
        ..., description="Representasi string persentase penurunan (contoh: '25%')"
    )
    affected_techniques: List[str] = Field(
        ..., description="Daftar Technique ID yang berhasil dimitigasi oleh kontrol ini"
    )

class RemovedNode(BaseModel):
    step_id: str = Field(..., description="ID node yang dihapus")

    technique: str = Field(
        ..., description="MITRE ATT&CK Technique ID"
    )

    tactic: Optional[str] = Field(
        default=None,
        description="MITRE ATT&CK Tactic"
    )

    reason: str = Field(
        ...,
        description="Alasan node dihapus (Blocked Technique / Unreachable)"
    )

class SimulationMetrics(BaseModel):
    # Metrik Ancaman
    severity: str = Field(
        ..., description="Kategori tingkat keparahan (Critical, High, Medium, Low)"
    )
    risk_score: int = Field(..., description="Skor keparahan berbasis bobot taktik")
    kill_chain_completion: str = Field(
        ..., description="Persentase taktik yang berhasil dicapai dari total 14 taktik"
    )
    blast_radius: int = Field(
        ..., description="Jumlah total node yang berpotensi terdampak (dapat dicapai)"
    )
    complexity: str = Field(..., description="Kompleksitas serangan (Advanced / Basic)")
    critical_path: List[str] = Field(
        ..., description="Urutan ID node yang membentuk jalur serangan paling berisiko"
    )
    maturity_level: str = Field(
        default="Unknown",
        description="Tingkat kematangan (Maturity Level) dari arsitektur serangan",
    )

    # Metrik Graf (Topologi)
    node_count: int = Field(
        ..., description="Jumlah node (langkah serangan) yang tersisa di dalam graf"
    )
    edge_count: int = Field(
        ..., description="Jumlah edge (hubungan/transisi) yang tersisa di dalam graf"
    )
    graph_density: float = Field(..., description="Kepadatan graf (0.0 - 1.0)")
    connected_components: int = Field(
        ..., description="Jumlah komponen (sub-graf) yang saling terhubung"
    )
    average_degree: float = Field(..., description="Rata-rata jumlah koneksi per node")


class SimulationComparison(BaseModel):
    severity_change: str = Field(
        ..., description="Perubahan severity, contoh: 'Critical -> Medium'"
    )
    risk_score_reduction: int = Field(..., description="Jumlah skor yang berkurang")
    kill_chain_reduction: str = Field(
        ..., description="Penurunan persentase kill chain, contoh: '-21.4%'"
    )
    blast_radius_reduction: int = Field(
        ..., description="Jumlah node terdampak yang berhasil diselamatkan"
    )
    complexity_change: str = Field(
        ..., description="Perubahan kompleksitas, contoh: 'Advanced -> Basic'"
    )


class SimulationResult(BaseModel):
    blocked_techniques: List[str] = Field(
        ..., description="Teknik yang digunakan sebagai input pemblokiran"
    )
    removed_nodes: List[Dict[str, Any]] = Field(
        ..., description="Daftar node yang terisolasi/terhapus akibat simulasi beserta detailnya"
    )
    removed_edges: List[Dict[str, Any]] = Field(
        ..., description="Daftar edge (source -> target) yang terhapus akibat simulasi beserta detailnya"
    )
    remaining_nodes: List[str] = Field(
        ..., description="Daftar node_id yang masih valid dan dapat dicapai"
    )

    metrics_before: SimulationMetrics
    metrics_after: SimulationMetrics
    comparison: SimulationComparison

    risk_reduction: int = Field(
        ..., description="Selisih nilai risk_score (metrics_before - metrics_after)"
    )
    attack_path_disruption_score: float = Field(
        ...,
        description="APDS: Metrik (0.0 - 100.0) persentase yang mengukur seberapa efektif pemotongan jalur memecah graf",
    )
    optimized_controls: List[OptimizedControl] = Field(
        ..., description="Daftar kontrol pertahanan diurutkan dari dampak terbesar"
    )
    simulation_summary: str = Field(
        ...,
        description="Narasi deterministik yang dihasilkan oleh rule engine (bukan AI)",
    )