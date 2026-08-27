"""
OCEAN Simulator – Viewer Server.

Exportiert Viewer-Daten und startet HTTP-Server.
Usage: python3 sim/serve.py [--port 8080] [--years 10] [--skip-export]
"""

import http.server
import os
import sys
import webbrowser

PORT = 8080
YEARS = 10
SIM_DIR = os.path.dirname(os.path.abspath(__file__))

if __name__ == "__main__":
    args = sys.argv[1:]

    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            PORT = int(args[i + 1])
        if a == "--years" and i + 1 < len(args):
            YEARS = int(args[i + 1])

    if "--skip-export" not in args:
        sys.path.insert(0, SIM_DIR)
        import time
        from export_viewer import export_viewer_data
        from init_gpu import init_world
        from tick_gpu import run
        from world import DEVICE, load_config
        from osm import (
            fetch_buildings, parse_buildings, settlements_with_coords,
            assign_buildings_to_settlements, select_usable_buildings,
            assign_npcs_to_buildings,
        )

        config, layout, sim = load_config()
        world = init_world().to(DEVICE)

        print(f"  Simuliere {YEARS} Jahre auf {DEVICE} ...")
        t0 = time.time()
        run(world, 52 * YEARS)
        world = world.to("cpu")
        print(f"  {52 * YEARS} Ticks in {time.time() - t0:.1f}s, "
              f"{world.n_alive} NPCs, {world.event_cursor} Ereignisse")

        bbox = config["meta"].get("osm_bbox")
        if bbox:
            settlements = settlements_with_coords(config)
            osm = fetch_buildings(bbox)
            buildings = parse_buildings(osm)
            by_settlement = assign_buildings_to_settlements(buildings, settlements)
            usable = select_usable_buildings(
                by_settlement, config["meta"].get("buildings_usable_pct", 0.02))
            assign_npcs_to_buildings(world, usable)

        export_viewer_data(world, config, path=os.path.join(SIM_DIR, "viewer_data.json"))

    os.chdir(SIM_DIR)
    handler = http.server.SimpleHTTPRequestHandler
    server = http.server.HTTPServer(("", PORT), handler)
    url = f"http://localhost:{PORT}/viewer.html"
    print(f"\n  Viewer: {url}\n")
    webbrowser.open(url)
    server.serve_forever()
