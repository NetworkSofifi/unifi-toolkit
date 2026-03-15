"""
API endpoints for Network Pulse dashboard data
"""
from fastapi import APIRouter, Depends, HTTPException

from tools.network_pulse.scheduler import get_cached_data, get_last_refresh, get_last_error
from tools.network_pulse.models import DashboardData, SystemStatus
from shared.controller_context import ControllerContext, get_controller_context

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("", response_model=DashboardData)
async def get_stats(
    controller: ControllerContext = Depends(get_controller_context),
):
    """
    Get all dashboard statistics in one call.

    Returns complete dashboard data including:
    - Gateway health (CPU, RAM, uptime, WAN status)
    - Device counts
    - Current throughput
    - Bandwidth history (24 hours)
    - AP status list
    - Top clients by bandwidth
    - Network health by subsystem
    """
    cached = get_cached_data(controller.controller_key)
    if cached is None:
        raise HTTPException(
            status_code=503,
            detail="Dashboard data not yet available. Please wait for initial refresh."
        )
    return cached


@router.get("/gateway")
async def get_gateway_stats(
    controller: ControllerContext = Depends(get_controller_context),
):
    """Get just the gateway health statistics"""
    cached = get_cached_data(controller.controller_key)
    if cached is None:
        raise HTTPException(status_code=503, detail="Data not available")
    return cached.gateway


@router.get("/bandwidth")
async def get_bandwidth_stats(
    controller: ControllerContext = Depends(get_controller_context),
):
    """
    Get bandwidth data for charts.

    Returns:
    - current_tx_rate: Current upload rate (bytes/sec)
    - current_rx_rate: Current download rate (bytes/sec)
    - bandwidth_history: List of hourly data points
    """
    cached = get_cached_data(controller.controller_key)
    if cached is None:
        raise HTTPException(status_code=503, detail="Data not available")
    return {
        "current_tx_rate": cached.current_tx_rate,
        "current_rx_rate": cached.current_rx_rate,
        "bandwidth_history": [p.model_dump() for p in cached.bandwidth_history]
    }


@router.get("/aps")
async def get_ap_stats(
    controller: ControllerContext = Depends(get_controller_context),
):
    """Get access point status list"""
    cached = get_cached_data(controller.controller_key)
    if cached is None:
        raise HTTPException(status_code=503, detail="Data not available")
    return {"access_points": [ap.model_dump() for ap in cached.access_points]}


@router.get("/clients")
async def get_top_clients(
    controller: ControllerContext = Depends(get_controller_context),
):
    """Get top clients by bandwidth usage"""
    cached = get_cached_data(controller.controller_key)
    if cached is None:
        raise HTTPException(status_code=503, detail="Data not available")
    return {"top_clients": [c.model_dump() for c in cached.top_clients]}


@router.get("/health")
async def get_network_health(
    controller: ControllerContext = Depends(get_controller_context),
):
    """Get network health by subsystem"""
    cached = get_cached_data(controller.controller_key)
    if cached is None:
        raise HTTPException(status_code=503, detail="Data not available")
    return cached.health.model_dump()


@router.get("/devices")
async def get_device_counts(
    controller: ControllerContext = Depends(get_controller_context),
):
    """Get device counts summary"""
    cached = get_cached_data(controller.controller_key)
    if cached is None:
        raise HTTPException(status_code=503, detail="Data not available")
    return cached.devices.model_dump()


@router.get("/ap/{ap_mac}")
async def get_ap_detail(
    ap_mac: str,
    controller: ControllerContext = Depends(get_controller_context),
):
    """
    Get detailed information about a specific AP and its connected clients.

    Args:
        ap_mac: MAC address of the access point

    Returns:
        - ap_info: AP details (name, model, uptime, channels, satisfaction)
        - clients: List of clients connected to this AP
        - clients_by_band: Radio band distribution for this AP
    """
    cached = get_cached_data(controller.controller_key)
    if cached is None:
        raise HTTPException(status_code=503, detail="Data not available")

    # Normalize MAC for comparison (lowercase with colons)
    ap_mac_normalized = ap_mac.lower().replace('-', ':')

    # Find the AP
    ap_info = None
    for ap in cached.access_points:
        if ap.mac.lower() == ap_mac_normalized:
            ap_info = ap
            break

    if ap_info is None:
        raise HTTPException(status_code=404, detail="AP not found")

    # Filter clients for this AP
    ap_clients = [
        client for client in cached.all_clients
        if client.ap_mac and client.ap_mac.lower() == ap_mac_normalized
    ]

    # Aggregate by band for this AP
    clients_by_band = {}
    for client in ap_clients:
        if client.is_wired:
            band_key = "Wired"
        elif client.radio:
            band_key = client.radio
        else:
            band_key = "Unknown"
        clients_by_band[band_key] = clients_by_band.get(band_key, 0) + 1

    return {
        "ap_info": ap_info.model_dump(),
        "clients": [c.model_dump() for c in ap_clients],
        "clients_by_band": clients_by_band
    }
