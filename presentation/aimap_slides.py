"""
AIMap — Hackathon Presentation
"nmap for the Agentic Era"

Render all slides:
    manim -qh --fps 30 aimap_slides.py

Render individual scene:
    manim -qh --fps 30 aimap_slides.py TitleSlide
"""

from manim import *
import numpy as np

# ─── Global Theme ──────────────────────────────────────────────────────────────

BG = "#0a0a0f"
SURFACE = "#131320"
SURFACE_2 = "#1a1a2e"
BORDER = "#2a2a3e"
TEXT_PRIMARY = "#e2e2f0"
TEXT_MUTED = "#8888a0"
ACCENT_BLUE = "#3b82f6"
ACCENT_CYAN = "#06b6d4"
ACCENT_PURPLE = "#8b5cf6"
ACCENT_GREEN = "#10b981"
ACCENT_AMBER = "#f59e0b"
SEVERITY_CRITICAL = "#ef4444"
SEVERITY_HIGH = "#f97316"
SEVERITY_MEDIUM = "#eab308"
SEVERITY_LOW = "#22c55e"
GLOW_BLUE = "#3b82f680"

config.background_color = BG
config.frame_width = 16
config.frame_height = 9


# ─── Helpers ───────────────────────────────────────────────────────────────────

def slide_title(text, color=ACCENT_BLUE):
    return Text(text, font="SF Mono", font_size=20, color=color, weight=BOLD).to_edge(UL, buff=0.5)


def section_badge(text, color=ACCENT_BLUE):
    label = Text(text, font="SF Mono", font_size=14, color=color, weight=BOLD)
    bg = SurroundingRectangle(label, color=color, fill_color=color, fill_opacity=0.12, corner_radius=0.08, buff=0.12, stroke_width=1)
    return VGroup(bg, label)


def stat_card(value, label, color=ACCENT_BLUE, width=3.2, height=1.8):
    card = RoundedRectangle(corner_radius=0.1, width=width, height=height, fill_color=SURFACE, fill_opacity=1, stroke_color=BORDER, stroke_width=1)
    val_text = Text(str(value), font="SF Mono", font_size=42, color=color, weight=BOLD)
    lab_text = Text(label, font="SF Mono", font_size=14, color=TEXT_MUTED)
    content = VGroup(val_text, lab_text).arrange(DOWN, buff=0.15)
    return VGroup(card, content)


def code_block(code_str, width=12, font_size=14):
    code = Code(
        code=code_str,
        language="python",
        font_size=font_size,
        background="rectangle",
        background_stroke_color=BORDER,
        insert_line_no=False,
        style="monokai",
    )
    return code


def glow_dot(pos, color=ACCENT_BLUE, radius=0.06):
    outer = Dot(pos, radius=radius * 3, color=color, fill_opacity=0.15)
    inner = Dot(pos, radius=radius, color=color, fill_opacity=0.9)
    return VGroup(outer, inner)


def animated_underline(mob, color=ACCENT_BLUE, width=2):
    line = Line(
        mob.get_left() + DOWN * 0.15,
        mob.get_right() + DOWN * 0.15,
        color=color,
        stroke_width=width,
    )
    return line


def hacker_terminal_line(text, color=ACCENT_GREEN, prefix="> ", font_size=16):
    return Text(f"{prefix}{text}", font="SF Mono", font_size=font_size, color=color)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 1: TITLE
# ═══════════════════════════════════════════════════════════════════════════════

class TitleSlide(Scene):
    def construct(self):
        # Background grid pattern
        grid_lines = VGroup()
        for x in np.arange(-8, 8.5, 0.5):
            grid_lines.add(Line(
                [x, -5, 0], [x, 5, 0],
                stroke_color=BORDER, stroke_width=0.3, stroke_opacity=0.2
            ))
        for y in np.arange(-5, 5.5, 0.5):
            grid_lines.add(Line(
                [-8, y, 0], [8, y, 0],
                stroke_color=BORDER, stroke_width=0.3, stroke_opacity=0.2
            ))
        self.add(grid_lines)

        # Scanning radar sweep
        radar_circle = Circle(radius=3.5, color=ACCENT_BLUE, stroke_width=1, stroke_opacity=0.15)
        radar_circle2 = Circle(radius=2.2, color=ACCENT_BLUE, stroke_width=1, stroke_opacity=0.1)
        radar_circle3 = Circle(radius=1.0, color=ACCENT_BLUE, stroke_width=1, stroke_opacity=0.08)

        sweep_line = Line(ORIGIN, [3.5, 0, 0], color=ACCENT_BLUE, stroke_width=2, stroke_opacity=0.4)
        sweep_sector = AnnularSector(
            inner_radius=0, outer_radius=3.5,
            angle=PI / 6, start_angle=0,
            fill_color=ACCENT_BLUE, fill_opacity=0.04,
            stroke_width=0,
        )
        radar = VGroup(radar_circle, radar_circle2, radar_circle3, sweep_sector, sweep_line)
        radar.shift(DOWN * 0.5)
        self.add(radar)
        self.play(Rotate(sweep_line, angle=TAU, about_point=radar.get_center(), rate_func=linear, run_time=6),
                  Rotate(sweep_sector, angle=TAU, about_point=radar.get_center(), rate_func=linear, run_time=6),
                  rate_func=linear, run_time=0.01)

        # Blips appearing on radar
        blip_positions = [
            radar.get_center() + np.array([1.5, 0.8, 0]),
            radar.get_center() + np.array([-2.0, -0.5, 0]),
            radar.get_center() + np.array([0.5, -1.8, 0]),
            radar.get_center() + np.array([-1.2, 1.5, 0]),
            radar.get_center() + np.array([2.5, -1.0, 0]),
            radar.get_center() + np.array([-0.8, -2.2, 0]),
        ]
        blip_colors = [SEVERITY_CRITICAL, SEVERITY_HIGH, ACCENT_GREEN, SEVERITY_MEDIUM, SEVERITY_CRITICAL, ACCENT_BLUE]

        # Title elements
        title = Text("AIMap", font="SF Mono", font_size=72, color=TEXT_PRIMARY, weight=BOLD)
        title.shift(UP * 2.8)

        tagline = Text("nmap for the Agentic Era", font="SF Mono", font_size=24, color=ACCENT_CYAN)
        tagline.next_to(title, DOWN, buff=0.3)

        underline = Line(
            tagline.get_left() + DOWN * 0.2 + LEFT * 0.3,
            tagline.get_right() + DOWN * 0.2 + RIGHT * 0.3,
            color=ACCENT_BLUE, stroke_width=2, stroke_opacity=0.6
        )

        subtitle = Text(
            "Discover, Fingerprint & Exploit Exposed AI Agents at Scale",
            font="SF Mono", font_size=16, color=TEXT_MUTED
        )
        subtitle.shift(DOWN * 3.5)

        # Animate
        self.play(
            Write(title, run_time=1.5),
            Rotate(sweep_line, angle=TAU, about_point=radar.get_center(), rate_func=linear, run_time=6),
            Rotate(sweep_sector, angle=TAU, about_point=radar.get_center(), rate_func=linear, run_time=6),
        )
        self.play(FadeIn(tagline, shift=UP * 0.3), Create(underline))

        # Blips appear one by one
        blips = VGroup()
        for pos, col in zip(blip_positions, blip_colors):
            blip = glow_dot(pos, color=col, radius=0.05)
            blips.add(blip)

        self.play(
            LaggedStart(*[FadeIn(b, scale=3) for b in blips], lag_ratio=0.15),
            FadeIn(subtitle, shift=UP * 0.2),
            run_time=2
        )

        # Pulse blips
        self.play(
            *[b[0].animate.scale(1.3).set_opacity(0.25) for b in blips],
            *[b[0].animate.scale(1/1.3).set_opacity(0.15) for b in blips],
            rate_func=there_and_back,
            run_time=1.5
        )

        self.wait(2)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 2: THE PROBLEM — EXPOSED AI INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════

class ProblemSlide(Scene):
    def construct(self):
        header = slide_title("THE PROBLEM")
        self.play(FadeIn(header, shift=RIGHT * 0.3))

        main_text = Text(
            "AI infrastructure is being deployed at breakneck speed.\nSecurity is an afterthought.",
            font="SF Mono", font_size=22, color=TEXT_PRIMARY, line_spacing=1.4
        )
        main_text.shift(UP * 2.5)
        self.play(Write(main_text, run_time=2))

        # Big stat cards
        card1 = stat_card("175,000+", "Ollama servers\nexposed globally", SEVERITY_CRITICAL, width=4.2, height=2.2)
        card2 = stat_card("2,000+", "Clawdbot gateways\nno authentication", SEVERITY_HIGH, width=4.2, height=2.2)
        card3 = stat_card("7,000+", "MCP servers\nopen on the web", ACCENT_AMBER, width=4.2, height=2.2)

        cards = VGroup(card1, card2, card3).arrange(RIGHT, buff=0.4)
        cards.shift(DOWN * 0.3)

        self.play(LaggedStart(
            *[FadeIn(c, shift=UP * 0.5, scale=0.9) for c in cards],
            lag_ratio=0.2
        ), run_time=2)

        # Bottom stats bar
        bottom_stats = VGroup(
            Text("43% of MCP servers have command injection", font="SF Mono", font_size=14, color=SEVERITY_CRITICAL),
            Text("  |  ", font="SF Mono", font_size=14, color=BORDER),
            Text("$100K/day in stolen compute", font="SF Mono", font_size=14, color=SEVERITY_HIGH),
            Text("  |  ", font="SF Mono", font_size=14, color=BORDER),
            Text("91,403 attack sessions documented", font="SF Mono", font_size=14, color=ACCENT_AMBER),
        ).arrange(RIGHT, buff=0.05)
        bottom_stats.shift(DOWN * 2.8)

        self.play(FadeIn(bottom_stats, shift=UP * 0.2))

        # Source citation
        source = Text(
            "Sources: SentinelOne/Censys Jan 2026, Shodan Jan 2026, AuthZed Dec 2025",
            font="SF Mono", font_size=10, color=TEXT_MUTED
        )
        source.to_edge(DOWN, buff=0.3)
        self.play(FadeIn(source))

        self.wait(3)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 3: REAL-WORLD BREACHES TIMELINE
# ═══════════════════════════════════════════════════════════════════════════════

class BreachesSlide(Scene):
    def construct(self):
        header = slide_title("REAL-WORLD BREACHES", SEVERITY_CRITICAL)
        self.play(FadeIn(header, shift=RIGHT * 0.3))

        breaches = [
            {
                "date": "JUN 2024",
                "title": "Probllama RCE (CVE-2024-37032)",
                "detail": "Remote code execution via Ollama model pull",
                "color": SEVERITY_CRITICAL,
            },
            {
                "date": "JAN 2025",
                "title": "DeepSeek Database Exposed",
                "detail": "1M+ chat logs, API keys leaked via open ClickHouse",
                "color": SEVERITY_CRITICAL,
            },
            {
                "date": "MAY 2025",
                "title": "xAI API Key Leaked on GitHub",
                "detail": "Access to 60+ private LLMs (SpaceX, Tesla data)",
                "color": SEVERITY_HIGH,
            },
            {
                "date": "SEP 2025",
                "title": "First Malicious MCP Server",
                "detail": "postmark-mcp on npm: 1,643 downloads, email exfil",
                "color": SEVERITY_CRITICAL,
            },
            {
                "date": "DEC 2025",
                "title": "LangGrinch (CVE-2025-68664)",
                "detail": "CVSS 9.3 serialization injection in LangChain",
                "color": SEVERITY_CRITICAL,
            },
            {
                "date": "JAN 2026",
                "title": "Clawdbot Mass Exposure",
                "detail": "2,000+ gateways: API keys, PII, root shells",
                "color": SEVERITY_HIGH,
            },
        ]

        # Timeline line
        timeline_y = 0.3
        line_start = LEFT * 6.5 + UP * timeline_y
        line_end = RIGHT * 6.5 + UP * timeline_y
        timeline_line = Line(line_start, line_end, color=BORDER, stroke_width=2)
        self.play(Create(timeline_line))

        items = VGroup()
        x_positions = np.linspace(-5.5, 5.5, len(breaches))

        for i, (breach, x) in enumerate(zip(breaches, x_positions)):
            dot = Dot([x, timeline_y, 0], color=breach["color"], radius=0.1)
            dot_glow = Dot([x, timeline_y, 0], color=breach["color"], radius=0.25, fill_opacity=0.2)

            # Alternate above/below
            direction = UP if i % 2 == 0 else DOWN
            offset = 1.8 if i % 2 == 0 else 1.8

            date_text = Text(breach["date"], font="SF Mono", font_size=11, color=breach["color"], weight=BOLD)
            title_text = Text(breach["title"], font="SF Mono", font_size=12, color=TEXT_PRIMARY, weight=BOLD)
            detail_text = Text(breach["detail"], font="SF Mono", font_size=10, color=TEXT_MUTED)

            label = VGroup(date_text, title_text, detail_text).arrange(DOWN, buff=0.08, aligned_edge=LEFT)
            label.move_to([x, timeline_y + direction[1] * offset, 0])

            connector = Line(
                [x, timeline_y, 0],
                [x, timeline_y + direction[1] * (offset - 0.6), 0],
                color=breach["color"], stroke_width=1, stroke_opacity=0.5
            )

            item = VGroup(dot_glow, dot, connector, label)
            items.add(item)

        self.play(LaggedStart(
            *[FadeIn(item, shift=UP * 0.3 if i % 2 == 0 else DOWN * 0.3)
              for i, item in enumerate(items)],
            lag_ratio=0.3
        ), run_time=4)

        # Takeaway
        takeaway = Text(
            "The attack surface is growing faster than security teams can respond.",
            font="SF Mono", font_size=16, color=SEVERITY_CRITICAL, weight=BOLD
        )
        takeaway.to_edge(DOWN, buff=0.5)
        self.play(FadeIn(takeaway, shift=UP * 0.2))

        self.wait(3)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 4: WHAT IS AIMAP
# ═══════════════════════════════════════════════════════════════════════════════

class WhatIsSlide(Scene):
    def construct(self):
        header = slide_title("WHAT IS AIMAP?")
        self.play(FadeIn(header, shift=RIGHT * 0.3))

        # Central definition
        defn = VGroup(
            Text("AIMap", font="SF Mono", font_size=36, color=ACCENT_CYAN, weight=BOLD),
            Text("is an end-to-end platform for", font="SF Mono", font_size=20, color=TEXT_MUTED),
        ).arrange(RIGHT, buff=0.3)
        defn.shift(UP * 3)

        pillars_data = [
            ("DISCOVER", "Scan the internet for\nexposed AI agents", ACCENT_BLUE, "01"),
            ("FINGERPRINT", "Identify protocols, tools,\nmodels & misconfigurations", ACCENT_CYAN, "02"),
            ("EXPLOIT", "Run protocol-aware attacks\nto prove real risk", SEVERITY_CRITICAL, "03"),
            ("MONITOR", "Track ranges over time\nwith continuous scanning", ACCENT_GREEN, "04"),
        ]

        pillars = VGroup()
        for label, desc, color, num in pillars_data:
            card = RoundedRectangle(
                corner_radius=0.1, width=3.4, height=3.2,
                fill_color=SURFACE, fill_opacity=1,
                stroke_color=color, stroke_width=1.5
            )
            num_text = Text(num, font="SF Mono", font_size=48, color=color, fill_opacity=0.15, weight=BOLD)
            num_text.move_to(card.get_center() + UP * 0.8 + RIGHT * 0.8)
            title = Text(label, font="SF Mono", font_size=18, color=color, weight=BOLD)
            title.move_to(card.get_center() + UP * 0.3)
            description = Text(desc, font="SF Mono", font_size=12, color=TEXT_MUTED, line_spacing=1.3)
            description.move_to(card.get_center() + DOWN * 0.6)

            # Top accent line
            accent = Line(
                card.get_top() + LEFT * 1.5 + DOWN * 0.01,
                card.get_top() + RIGHT * 1.5 + DOWN * 0.01,
                color=color, stroke_width=3
            )
            pillar = VGroup(card, num_text, accent, title, description)
            pillars.add(pillar)

        pillars.arrange(RIGHT, buff=0.3)
        pillars.shift(DOWN * 0.3)

        self.play(Write(defn, run_time=1))

        # Arrows between pillars
        arrows = VGroup()
        for i in range(len(pillars) - 1):
            arr = Arrow(
                pillars[i].get_right() + LEFT * 0.1,
                pillars[i + 1].get_left() + RIGHT * 0.1,
                color=TEXT_MUTED, stroke_width=1.5, buff=0.1,
                max_tip_length_to_length_ratio=0.15
            )
            arrows.add(arr)

        self.play(LaggedStart(
            *[FadeIn(p, shift=UP * 0.5) for p in pillars],
            lag_ratio=0.15
        ), run_time=2)
        self.play(LaggedStart(*[GrowArrow(a) for a in arrows], lag_ratio=0.2))

        # Bottom: protocol support
        proto_text = Text("14+ AI protocols supported", font="SF Mono", font_size=14, color=TEXT_MUTED)
        protos = VGroup(
            section_badge("MCP", ACCENT_BLUE),
            section_badge("Ollama", ACCENT_GREEN),
            section_badge("OpenAI", ACCENT_PURPLE),
            section_badge("LangServe", ACCENT_CYAN),
            section_badge("OpenClaw", SEVERITY_HIGH),
            section_badge("Gradio", ACCENT_AMBER),
            section_badge("ComfyUI", SEVERITY_MEDIUM),
            section_badge("+ 7 more", TEXT_MUTED),
        ).arrange(RIGHT, buff=0.2)
        bottom = VGroup(proto_text, protos).arrange(DOWN, buff=0.2)
        bottom.to_edge(DOWN, buff=0.4)

        self.play(FadeIn(bottom, shift=UP * 0.2))
        self.wait(3)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 5: ARCHITECTURE
# ═══════════════════════════════════════════════════════════════════════════════

class ArchitectureSlide(Scene):
    def construct(self):
        header = slide_title("ARCHITECTURE")
        self.play(FadeIn(header, shift=RIGHT * 0.3))

        # Layer boxes
        def layer_box(title, items, color, width=14, height=1.5):
            box = RoundedRectangle(
                corner_radius=0.1, width=width, height=height,
                fill_color=SURFACE, fill_opacity=0.9,
                stroke_color=color, stroke_width=1.5
            )
            title_t = Text(title, font="SF Mono", font_size=16, color=color, weight=BOLD)
            title_t.move_to(box.get_left() + RIGHT * 1.5)
            items_group = VGroup()
            for item in items:
                badge = section_badge(item, color)
                items_group.add(badge)
            items_group.arrange(RIGHT, buff=0.3)
            items_group.move_to(box.get_center() + RIGHT * 1)
            return VGroup(box, title_t, items_group)

        frontend = layer_box("FRONTEND", ["React 18", "Vite", "Globe.gl", "Recharts", "shadcn/ui"], ACCENT_BLUE, height=1.2)
        api = layer_box("API LAYER", ["FastAPI", "WebSocket", "REST", "Streaming"], ACCENT_CYAN, height=1.2)
        services = layer_box("SERVICES", ["Attack Engines", "Enrichment", "Risk Scoring", "Search"], ACCENT_PURPLE, height=1.2)
        discovery = layer_box("DISCOVERY", ["Shodan", "Censys", "Nuclei", "httpx", "FOFA"], ACCENT_GREEN, height=1.2)
        storage = layer_box("STORAGE", ["MongoDB", "Celery", "Redis"], ACCENT_AMBER, height=1.2)

        stack = VGroup(frontend, api, services, discovery, storage).arrange(DOWN, buff=0.25)
        stack.shift(DOWN * 0.2)

        # Animate layers building up from bottom
        layers = [storage, discovery, services, api, frontend]
        self.play(LaggedStart(
            *[FadeIn(l, shift=UP * 0.5) for l in layers],
            lag_ratio=0.2
        ), run_time=3)

        # Connection arrows on the right side
        for i in range(len(layers) - 1):
            arrow = Arrow(
                layers[i][0].get_top(),
                layers[i + 1][0].get_bottom(),
                color=TEXT_MUTED, stroke_width=1, buff=0.05,
                max_tip_length_to_length_ratio=0.2
            )
            self.play(GrowArrow(arrow), run_time=0.3)

        self.wait(3)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 6: DISCOVERY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class DiscoverySlide(Scene):
    def construct(self):
        header = slide_title("DISCOVERY ENGINE")
        self.play(FadeIn(header, shift=RIGHT * 0.3))

        # Pipeline visualization
        stages = [
            ("INTERNET\nSCANNERS", "Shodan / Censys\nFOFA / ZoomEye", ACCENT_BLUE),
            ("HOST\nPROBING", "httpx alive sweep\nacross port ranges", ACCENT_CYAN),
            ("PROTOCOL\nDETECTION", "Custom Nuclei YAML\ntemplates (6+)", ACCENT_PURPLE),
            ("ENRICHMENT", "Tool extraction\nRisk scoring", ACCENT_GREEN),
            ("AGENT\nINVENTORY", "MongoDB with\nfull fingerprint", ACCENT_AMBER),
        ]

        pipeline = VGroup()
        for title, desc, color in stages:
            box = RoundedRectangle(
                corner_radius=0.1, width=2.5, height=2.8,
                fill_color=SURFACE, fill_opacity=1,
                stroke_color=color, stroke_width=1.5
            )
            accent = Line(
                box.get_top() + LEFT * 1 + DOWN * 0.01,
                box.get_top() + RIGHT * 1 + DOWN * 0.01,
                color=color, stroke_width=3
            )
            t = Text(title, font="SF Mono", font_size=13, color=color, weight=BOLD, line_spacing=1.2)
            t.move_to(box.get_center() + UP * 0.5)
            d = Text(desc, font="SF Mono", font_size=10, color=TEXT_MUTED, line_spacing=1.2)
            d.move_to(box.get_center() + DOWN * 0.5)
            pipeline.add(VGroup(box, accent, t, d))

        pipeline.arrange(RIGHT, buff=0.35)
        pipeline.shift(UP * 0.5)

        self.play(LaggedStart(
            *[FadeIn(p, shift=RIGHT * 0.5) for p in pipeline],
            lag_ratio=0.2
        ), run_time=2.5)

        # Arrows
        for i in range(len(pipeline) - 1):
            arrow = Arrow(
                pipeline[i][0].get_right(),
                pipeline[i + 1][0].get_left(),
                color=TEXT_MUTED, stroke_width=1.5, buff=0.05,
                max_tip_length_to_length_ratio=0.2
            )
            self.play(GrowArrow(arrow), run_time=0.3)

        # Bottom: Nuclei template example
        template_title = Text("Custom Nuclei Templates", font="SF Mono", font_size=14, color=ACCENT_PURPLE, weight=BOLD)
        templates = VGroup(
            section_badge("mcp-server-detect.yaml", ACCENT_BLUE),
            section_badge("mcp-tool-enum.yaml", ACCENT_BLUE),
            section_badge("langserve-detect.yaml", ACCENT_CYAN),
            section_badge("openai-compat-detect.yaml", ACCENT_PURPLE),
            section_badge("prompt-leak.yaml", SEVERITY_CRITICAL),
        ).arrange(RIGHT, buff=0.15)
        bottom = VGroup(template_title, templates).arrange(DOWN, buff=0.2)
        bottom.shift(DOWN * 2.5)

        self.play(FadeIn(bottom, shift=UP * 0.2))
        self.wait(3)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 7: ATTACK ENGINES
# ═══════════════════════════════════════════════════════════════════════════════

class AttackEnginesSlide(Scene):
    def construct(self):
        header = slide_title("PROTOCOL-AWARE ATTACK ENGINES", SEVERITY_CRITICAL)
        self.play(FadeIn(header, shift=RIGHT * 0.3))

        engines = [
            {
                "name": "MCP Attack Engine",
                "color": ACCENT_BLUE,
                "attacks": [
                    "Unauth tool execution",
                    "Path traversal & file read",
                    "Remote code execution",
                    "SSRF to cloud metadata",
                    "Prompt injection",
                    "System prompt extraction",
                    "Data exfil via tool chains",
                ],
            },
            {
                "name": "Ollama Attack Engine",
                "color": ACCENT_GREEN,
                "attacks": [
                    "Model inventory & VRAM recon",
                    "System prompt extraction",
                    "Uncensored model detection",
                    "Admin ops (pull/delete/copy)",
                    "DAN-style jailbreaks",
                    "Safety bypass probes",
                    "Training data extraction",
                ],
            },
            {
                "name": "OpenClaw Attack Engine",
                "color": SEVERITY_HIGH,
                "attacks": [
                    "Default credential testing",
                    "Agent enumeration & config",
                    "API key harvesting",
                    "Execution log access",
                    "Malicious task injection",
                    "Plugin/extension abuse",
                    "User management access",
                ],
            },
        ]

        cards = VGroup()
        for eng in engines:
            card = RoundedRectangle(
                corner_radius=0.1, width=4.5, height=5.5,
                fill_color=SURFACE, fill_opacity=1,
                stroke_color=eng["color"], stroke_width=1.5
            )
            accent = Line(
                card.get_top() + LEFT * 2 + DOWN * 0.01,
                card.get_top() + RIGHT * 2 + DOWN * 0.01,
                color=eng["color"], stroke_width=3
            )
            title = Text(eng["name"], font="SF Mono", font_size=14, color=eng["color"], weight=BOLD)
            title.move_to(card.get_top() + DOWN * 0.5)

            attacks_group = VGroup()
            for i, atk in enumerate(eng["attacks"]):
                bullet = Text(f"  {atk}", font="SF Mono", font_size=11, color=TEXT_MUTED)
                dot = Dot(bullet.get_left() + LEFT * 0.15, radius=0.04, color=eng["color"])
                attacks_group.add(VGroup(dot, bullet))

            attacks_group.arrange(DOWN, buff=0.15, aligned_edge=LEFT)
            attacks_group.move_to(card.get_center() + DOWN * 0.3)

            cards.add(VGroup(card, accent, title, attacks_group))

        cards.arrange(RIGHT, buff=0.3)
        cards.shift(DOWN * 0.3)

        self.play(LaggedStart(
            *[FadeIn(c, shift=UP * 0.5) for c in cards],
            lag_ratio=0.2
        ), run_time=2.5)

        # Bottom: streaming badge
        streaming = VGroup(
            Text("LIVE STREAMING", font="SF Mono", font_size=12, color=ACCENT_CYAN, weight=BOLD),
            Text("  |  All results streamed via WebSocket in real-time", font="SF Mono", font_size=12, color=TEXT_MUTED),
        ).arrange(RIGHT, buff=0.1)
        streaming.to_edge(DOWN, buff=0.5)
        self.play(FadeIn(streaming, shift=UP * 0.2))

        self.wait(3)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 8: LIVE ATTACK DEMO FLOW
# ═══════════════════════════════════════════════════════════════════════════════

class LiveAttackSlide(Scene):
    def construct(self):
        header = slide_title("LIVE ATTACK: MCP SERVER", SEVERITY_CRITICAL)
        self.play(FadeIn(header, shift=RIGHT * 0.3))

        # Terminal window
        terminal_bg = RoundedRectangle(
            corner_radius=0.15, width=13, height=6.5,
            fill_color="#0d0d14", fill_opacity=1,
            stroke_color=BORDER, stroke_width=1.5
        )
        terminal_bg.shift(DOWN * 0.3)

        # Title bar
        title_bar = Rectangle(
            width=13, height=0.4,
            fill_color=SURFACE_2, fill_opacity=1,
            stroke_width=0
        )
        title_bar.move_to(terminal_bg.get_top() + DOWN * 0.2)
        dots = VGroup(
            Dot(title_bar.get_left() + RIGHT * 0.5, radius=0.06, color="#ff5f56"),
            Dot(title_bar.get_left() + RIGHT * 0.8, radius=0.06, color="#ffbd2e"),
            Dot(title_bar.get_left() + RIGHT * 1.1, radius=0.06, color="#27c93f"),
        )
        title_label = Text("AIMap Attack Console", font="SF Mono", font_size=11, color=TEXT_MUTED)
        title_label.move_to(title_bar.get_center())

        self.play(FadeIn(terminal_bg), FadeIn(title_bar), FadeIn(dots), FadeIn(title_label))

        # Simulated attack log lines
        lines_data = [
            ("[14:32:01]  REASONING  Initializing MCP attack against 52.14.88.201:8080", ACCENT_BLUE, 0.6),
            ("[14:32:02]  REASONING  Enumerating tools via tools/list...", ACCENT_BLUE, 0.4),
            ("[14:32:03]  RESPONSE   Found 6 tools: query_db, send_email, read_file, exec_cmd, fetch_url, write_file", TEXT_MUTED, 0.5),
            ("[14:32:04]  FINDING    CRITICAL  Tool 'exec_cmd' callable without authentication", SEVERITY_CRITICAL, 0.8),
            ("[14:32:05]  PAYLOAD    > {\"method\": \"exec_cmd\", \"params\": {\"command\": \"id\"}}", SEVERITY_HIGH, 0.5),
            ("[14:32:05]  RESPONSE   < uid=1000(app) gid=1000(app) groups=1000(app)", TEXT_MUTED, 0.5),
            ("[14:32:06]  FINDING    CRITICAL  Remote Code Execution confirmed via exec_cmd", SEVERITY_CRITICAL, 0.8),
            ("[14:32:07]  PAYLOAD    > Attempting SSRF via fetch_url -> 169.254.169.254", SEVERITY_HIGH, 0.5),
            ("[14:32:08]  RESPONSE   < {\"iam\": {\"role\": \"arn:aws:iam::role/prod-agent\"}}", TEXT_MUTED, 0.5),
            ("[14:32:09]  FINDING    HIGH  AWS metadata accessible — IAM role exposed", SEVERITY_HIGH, 0.7),
            ("[14:32:10]  REASONING  Chaining query_db -> send_email for data exfiltration...", ACCENT_BLUE, 0.5),
            ("[14:32:11]  FINDING    CRITICAL  Data exfiltration chain confirmed", SEVERITY_CRITICAL, 0.8),
        ]

        y_start = terminal_bg.get_top()[1] - 0.7
        lines_group = VGroup()

        for i, (text, color, wait) in enumerate(lines_data):
            line = Text(text, font="SF Mono", font_size=11, color=color)
            line.move_to([terminal_bg.get_left()[0] + 0.5 + line.width / 2, y_start - i * 0.42, 0])
            lines_group.add(line)

        for i, (line, (_, _, wait)) in enumerate(zip(lines_group, lines_data)):
            self.play(FadeIn(line, shift=LEFT * 0.3), run_time=wait)

        # Cursor blink
        cursor = Rectangle(width=0.08, height=0.25, fill_color=ACCENT_GREEN, fill_opacity=1, stroke_width=0)
        last_line = lines_group[-1]
        cursor.next_to(last_line, DOWN, buff=0.15, aligned_edge=LEFT)
        self.play(FadeIn(cursor))
        self.play(
            cursor.animate.set_opacity(0),
            rate_func=there_and_back,
            run_time=0.8
        )
        self.play(
            cursor.animate.set_opacity(1),
            rate_func=there_and_back,
            run_time=0.8
        )

        self.wait(2)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 9: 3D GLOBE & GEO VISUALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

class GlobeSlide(Scene):
    def construct(self):
        header = slide_title("GLOBAL THREAT MAP")
        self.play(FadeIn(header, shift=RIGHT * 0.3))

        # Simulated globe (circle with meridians)
        globe = Circle(radius=2.5, color=ACCENT_BLUE, stroke_width=1.5, stroke_opacity=0.4)
        globe.shift(LEFT * 2.5 + DOWN * 0.3)

        # Latitude lines
        lat_lines = VGroup()
        for y_offset in [-1.5, -0.75, 0, 0.75, 1.5]:
            half_width = np.sqrt(max(0, 2.5**2 - y_offset**2))
            if half_width > 0:
                ellipse = Ellipse(width=half_width * 2, height=0.3, color=ACCENT_BLUE, stroke_width=0.5, stroke_opacity=0.2)
                ellipse.move_to(globe.get_center() + UP * y_offset)
                lat_lines.add(ellipse)

        # Longitude lines
        lon_lines = VGroup()
        for angle in [0, PI / 4, PI / 2, 3 * PI / 4]:
            ell = Ellipse(width=1.0, height=5.0, color=ACCENT_BLUE, stroke_width=0.5, stroke_opacity=0.2)
            ell.move_to(globe.get_center())
            ell.rotate(angle)
            lon_lines.add(ell)

        self.play(Create(globe), FadeIn(lat_lines), FadeIn(lon_lines))

        # Threat pins
        pin_data = [
            (globe.get_center() + np.array([1.0, 0.8, 0]), SEVERITY_CRITICAL, "US — 847 agents"),
            (globe.get_center() + np.array([-0.5, 1.2, 0]), ACCENT_BLUE, "DE — 312 agents"),
            (globe.get_center() + np.array([2.0, -0.3, 0]), SEVERITY_HIGH, "CN — 523 agents"),
            (globe.get_center() + np.array([-1.5, -0.8, 0]), ACCENT_GREEN, "BR — 89 agents"),
            (globe.get_center() + np.array([0.8, -1.5, 0]), ACCENT_AMBER, "IN — 201 agents"),
            (globe.get_center() + np.array([-1.8, 0.5, 0]), ACCENT_CYAN, "GB — 167 agents"),
        ]

        pins = VGroup()
        for pos, color, label in pin_data:
            pin = VGroup(
                Line(pos, pos + UP * 0.4, color=color, stroke_width=2),
                Dot(pos + UP * 0.4, radius=0.08, color=color),
                Dot(pos + UP * 0.4, radius=0.2, color=color, fill_opacity=0.15),
            )
            pins.add(pin)

        self.play(LaggedStart(
            *[FadeIn(p, scale=2) for p in pins],
            lag_ratio=0.15
        ), run_time=2)

        # Feature list on right
        features_title = Text("GLOBE FEATURES", font="SF Mono", font_size=16, color=ACCENT_CYAN, weight=BOLD)
        features_title.move_to(RIGHT * 3.5 + UP * 2.5)

        feature_items = [
            "Interactive 3D WebGL globe",
            "Pins color-coded by protocol",
            "Pin height = risk severity",
            "Hover for endpoint details",
            "Click to navigate to agent",
            "Auto-rotate with idle resume",
            "Real-time data from API",
            "Protocol legend with counts",
        ]

        features = VGroup()
        for item in feature_items:
            dot = Dot(ORIGIN, radius=0.04, color=ACCENT_CYAN)
            text = Text(item, font="SF Mono", font_size=12, color=TEXT_MUTED)
            row = VGroup(dot, text).arrange(RIGHT, buff=0.2)
            features.add(row)

        features.arrange(DOWN, buff=0.25, aligned_edge=LEFT)
        features.next_to(features_title, DOWN, buff=0.3, aligned_edge=LEFT)

        self.play(FadeIn(features_title))
        self.play(LaggedStart(
            *[FadeIn(f, shift=LEFT * 0.2) for f in features],
            lag_ratio=0.1
        ), run_time=1.5)

        # Pulse effect on pins
        self.play(
            *[p[2].animate.scale(1.5).set_opacity(0.05) for p in pins],
            rate_func=there_and_back,
            run_time=1.5
        )

        self.wait(2)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 10: SCANNING & RANGE MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

class ScanningSlide(Scene):
    def construct(self):
        header = slide_title("SCANNING & RANGE MONITORING")
        self.play(FadeIn(header, shift=RIGHT * 0.3))

        # Left: Active Scanning
        scan_card = RoundedRectangle(
            corner_radius=0.1, width=6.5, height=5.5,
            fill_color=SURFACE, fill_opacity=1,
            stroke_color=ACCENT_BLUE, stroke_width=1.5
        )
        scan_card.shift(LEFT * 3.8 + DOWN * 0.3)
        scan_accent = Line(
            scan_card.get_top() + LEFT * 3 + DOWN * 0.01,
            scan_card.get_top() + RIGHT * 3 + DOWN * 0.01,
            color=ACCENT_BLUE, stroke_width=3
        )

        scan_title = Text("ACTIVE SCANNING", font="SF Mono", font_size=16, color=ACCENT_BLUE, weight=BOLD)
        scan_title.move_to(scan_card.get_top() + DOWN * 0.5)

        scan_features = VGroup(
            Text("  Custom CIDR range targeting", font="SF Mono", font_size=12, color=TEXT_MUTED),
            Text("  Multi-port sweep (80-8888)", font="SF Mono", font_size=12, color=TEXT_MUTED),
            Text("  Protocol-specific templates", font="SF Mono", font_size=12, color=TEXT_MUTED),
            Text("  Configurable rate limiting", font="SF Mono", font_size=12, color=TEXT_MUTED),
            Text("  Real-time WebSocket progress", font="SF Mono", font_size=12, color=TEXT_MUTED),
            Text("  Shodan/Censys ingestion", font="SF Mono", font_size=12, color=TEXT_MUTED),
        )
        for f in scan_features:
            dot = Dot(f.get_left() + LEFT * 0.15, radius=0.04, color=ACCENT_BLUE)
            f.add(dot)
        scan_features.arrange(DOWN, buff=0.2, aligned_edge=LEFT)
        scan_features.move_to(scan_card.get_center() + DOWN * 0.2)

        # Progress bar simulation
        progress_bg = RoundedRectangle(
            corner_radius=0.05, width=5, height=0.3,
            fill_color=SURFACE_2, fill_opacity=1,
            stroke_color=BORDER, stroke_width=1
        )
        progress_bg.move_to(scan_card.get_bottom() + UP * 0.7)
        progress_fill = RoundedRectangle(
            corner_radius=0.05, width=0, height=0.26,
            fill_color=ACCENT_BLUE, fill_opacity=0.8,
            stroke_width=0
        )
        progress_fill.move_to(progress_bg.get_left(), aligned_edge=LEFT)
        progress_text = Text("67% — 2,847/4,096 hosts scanned", font="SF Mono", font_size=10, color=TEXT_MUTED)
        progress_text.next_to(progress_bg, DOWN, buff=0.1)

        scan_group = VGroup(scan_card, scan_accent, scan_title, scan_features, progress_bg, progress_fill, progress_text)

        # Right: Range Monitoring
        range_card = RoundedRectangle(
            corner_radius=0.1, width=6.5, height=5.5,
            fill_color=SURFACE, fill_opacity=1,
            stroke_color=ACCENT_GREEN, stroke_width=1.5
        )
        range_card.shift(RIGHT * 3.8 + DOWN * 0.3)
        range_accent = Line(
            range_card.get_top() + LEFT * 3 + DOWN * 0.01,
            range_card.get_top() + RIGHT * 3 + DOWN * 0.01,
            color=ACCENT_GREEN, stroke_width=3
        )

        range_title = Text("RANGE MONITORING", font="SF Mono", font_size=16, color=ACCENT_GREEN, weight=BOLD)
        range_title.move_to(range_card.get_top() + DOWN * 0.5)

        range_features = VGroup(
            Text("  Define CIDR ranges to watch", font="SF Mono", font_size=12, color=TEXT_MUTED),
            Text("  Scheduled recurring scans", font="SF Mono", font_size=12, color=TEXT_MUTED),
            Text("  Trend tracking (7d / 30d)", font="SF Mono", font_size=12, color=TEXT_MUTED),
            Text("  Risk breakdown per range", font="SF Mono", font_size=12, color=TEXT_MUTED),
            Text("  New agent alerts", font="SF Mono", font_size=12, color=TEXT_MUTED),
            Text("  One-click scan-now", font="SF Mono", font_size=12, color=TEXT_MUTED),
        )
        for f in range_features:
            dot = Dot(f.get_left() + LEFT * 0.15, radius=0.04, color=ACCENT_GREEN)
            f.add(dot)
        range_features.arrange(DOWN, buff=0.2, aligned_edge=LEFT)
        range_features.move_to(range_card.get_center() + DOWN * 0.2)

        # Sparkline simulation
        spark_points = [
            [-2, 0, 0], [-1.5, 0.2, 0], [-1, 0.1, 0], [-0.5, 0.4, 0],
            [0, 0.3, 0], [0.5, 0.6, 0], [1, 0.5, 0], [1.5, 0.8, 0], [2, 1.0, 0]
        ]
        sparkline = VMobject(color=ACCENT_GREEN, stroke_width=2)
        sparkline.set_points_smoothly([np.array(p) for p in spark_points])
        sparkline.scale(0.5)
        sparkline.move_to(range_card.get_bottom() + UP * 0.8)
        spark_label = Text("Agent count trend (30d)", font="SF Mono", font_size=10, color=TEXT_MUTED)
        spark_label.next_to(sparkline, DOWN, buff=0.1)

        range_group = VGroup(range_card, range_accent, range_title, range_features, sparkline, spark_label)

        self.play(FadeIn(scan_group, shift=UP * 0.5), run_time=1.5)
        self.play(FadeIn(range_group, shift=UP * 0.5), run_time=1.5)

        # Animate progress bar
        self.play(
            progress_fill.animate.stretch_to_fit_width(3.35).move_to(progress_bg.get_left() + RIGHT * 1.675, aligned_edge=LEFT),
            run_time=2,
            rate_func=smooth
        )
        # Animate sparkline drawing
        self.play(Create(sparkline), run_time=1.5)

        self.wait(2)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 11: RISK SCORING & SEARCH
# ═══════════════════════════════════════════════════════════════════════════════

class RiskSearchSlide(Scene):
    def construct(self):
        header = slide_title("INTELLIGENT RISK SCORING")
        self.play(FadeIn(header, shift=RIGHT * 0.3))

        # Risk formula
        formula_title = Text("Dynamic Risk Score Algorithm", font="SF Mono", font_size=16, color=ACCENT_CYAN, weight=BOLD)
        formula_title.shift(UP * 3)

        factors = [
            ("No authentication", "+2.0", SEVERITY_CRITICAL),
            ("Weak authentication", "+1.5", SEVERITY_HIGH),
            ("Critical tool (exec_cmd, sql)", "+2.0 each", SEVERITY_CRITICAL),
            ("High-risk tool (file_read, http)", "+1.5 each", SEVERITY_HIGH),
            ("Dangerous combo (db + email)", "+1.5 each", SEVERITY_MEDIUM),
            ("System prompt leaked", "+0.5", ACCENT_AMBER),
        ]

        factor_group = VGroup()
        for name, score, color in factors:
            row_bg = RoundedRectangle(
                corner_radius=0.05, width=10, height=0.45,
                fill_color=SURFACE, fill_opacity=0.8,
                stroke_color=BORDER, stroke_width=0.5
            )
            name_t = Text(name, font="SF Mono", font_size=13, color=TEXT_MUTED)
            name_t.move_to(row_bg.get_left() + RIGHT * 2.5)
            score_t = Text(score, font="SF Mono", font_size=13, color=color, weight=BOLD)
            score_t.move_to(row_bg.get_right() + LEFT * 1.5)
            color_bar = Line(
                row_bg.get_left() + RIGHT * 0.05,
                row_bg.get_left() + RIGHT * 0.05 + UP * 0.15 + DOWN * 0.15,
                color=color, stroke_width=4
            )
            # Fix: just use a dot instead
            indicator = Dot(row_bg.get_left() + RIGHT * 0.3, radius=0.06, color=color)
            factor_group.add(VGroup(row_bg, name_t, score_t, indicator))

        factor_group.arrange(DOWN, buff=0.08)
        factor_group.shift(UP * 0.5)

        self.play(FadeIn(formula_title))
        self.play(LaggedStart(
            *[FadeIn(f, shift=LEFT * 0.3) for f in factor_group],
            lag_ratio=0.1
        ), run_time=2)

        # Risk scale bar
        scale_title = Text("Risk Scale", font="SF Mono", font_size=14, color=TEXT_MUTED)
        scale_title.shift(DOWN * 2.2)

        scale_items = [
            ("INFO", "0-0.9", "#6366f1"),
            ("LOW", "1-3.9", SEVERITY_LOW),
            ("MEDIUM", "4-6.9", SEVERITY_MEDIUM),
            ("HIGH", "7-8.9", SEVERITY_HIGH),
            ("CRITICAL", "9-10", SEVERITY_CRITICAL),
        ]

        scale_group = VGroup()
        for label, rng, color in scale_items:
            box = RoundedRectangle(
                corner_radius=0.05, width=2.4, height=0.7,
                fill_color=color, fill_opacity=0.15,
                stroke_color=color, stroke_width=1.5
            )
            lab = Text(label, font="SF Mono", font_size=12, color=color, weight=BOLD)
            rng_t = Text(rng, font="SF Mono", font_size=10, color=TEXT_MUTED)
            content = VGroup(lab, rng_t).arrange(DOWN, buff=0.05)
            content.move_to(box.get_center())
            scale_group.add(VGroup(box, content))

        scale_group.arrange(RIGHT, buff=0.15)
        scale_group.shift(DOWN * 3)

        self.play(FadeIn(scale_title), FadeIn(scale_group, shift=UP * 0.2))

        # Shodan-style search
        search_badge = section_badge("SHODAN-STYLE SEARCH", ACCENT_PURPLE)
        search_badge.to_edge(RIGHT, buff=0.8).shift(UP * 3)
        search_example = Text(
            'protocol:mcp auth:none\nrisk:critical tool:exec_cmd\ncountry:US has:system_prompt',
            font="SF Mono", font_size=11, color=ACCENT_PURPLE, line_spacing=1.4
        )
        search_example.next_to(search_badge, DOWN, buff=0.2)

        self.play(FadeIn(search_badge), FadeIn(search_example))

        self.wait(3)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 12: KEY DIFFERENTIATORS
# ═══════════════════════════════════════════════════════════════════════════════

class DifferentiatorsSlide(Scene):
    def construct(self):
        header = slide_title("WHY AIMAP?")
        self.play(FadeIn(header, shift=RIGHT * 0.3))

        diffs = [
            ("No existing tool does this", "There is no nmap, Burp Suite, or Shodan\nbuilt for the AI agent attack surface", ACCENT_BLUE),
            ("Protocol-native exploitation", "Not generic web fuzzing — attacks\nunderstand MCP, Ollama, OpenClaw APIs", SEVERITY_CRITICAL),
            ("Real-time streaming", "WebSocket-based live attack logs\nand scan progress — not batch reports", ACCENT_CYAN),
            ("End-to-end pipeline", "From Shodan query to confirmed exploit\nin a single platform", ACCENT_GREEN),
            ("Continuous monitoring", "Track your ranges over time\nGet alerts when new agents appear", ACCENT_AMBER),
            ("3D geospatial intelligence", "Globe visualization for threat\nawareness and pattern recognition", ACCENT_PURPLE),
        ]

        cards = VGroup()
        for title, desc, color in diffs:
            card = RoundedRectangle(
                corner_radius=0.1, width=4.8, height=2.0,
                fill_color=SURFACE, fill_opacity=1,
                stroke_color=color, stroke_width=1
            )
            accent = Line(
                card.get_left() + RIGHT * 0.01 + UP * 0.7,
                card.get_left() + RIGHT * 0.01 + DOWN * 0.7,
                color=color, stroke_width=3
            )
            t = Text(title, font="SF Mono", font_size=13, color=color, weight=BOLD)
            t.move_to(card.get_center() + UP * 0.4 + LEFT * 0.2)
            d = Text(desc, font="SF Mono", font_size=10, color=TEXT_MUTED, line_spacing=1.3)
            d.move_to(card.get_center() + DOWN * 0.35 + LEFT * 0.2)
            cards.add(VGroup(card, accent, t, d))

        # 3x2 grid
        row1 = VGroup(cards[0], cards[1], cards[2]).arrange(RIGHT, buff=0.25)
        row2 = VGroup(cards[3], cards[4], cards[5]).arrange(RIGHT, buff=0.25)
        grid = VGroup(row1, row2).arrange(DOWN, buff=0.25)
        grid.shift(DOWN * 0.3)

        self.play(LaggedStart(
            *[FadeIn(c, shift=UP * 0.3) for c in cards],
            lag_ratio=0.12
        ), run_time=3)

        self.wait(3)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 13: DEMO / CALL TO ACTION
# ═══════════════════════════════════════════════════════════════════════════════

class DemoSlide(Scene):
    def construct(self):
        # Background grid
        grid_lines = VGroup()
        for x in np.arange(-8, 8.5, 1):
            grid_lines.add(Line(
                [x, -5, 0], [x, 5, 0],
                stroke_color=BORDER, stroke_width=0.3, stroke_opacity=0.15
            ))
        for y in np.arange(-5, 5.5, 1):
            grid_lines.add(Line(
                [-8, y, 0], [8, y, 0],
                stroke_color=BORDER, stroke_width=0.3, stroke_opacity=0.15
            ))
        self.add(grid_lines)

        # "DEMO" text
        demo = Text("LIVE DEMO", font="SF Mono", font_size=64, color=ACCENT_CYAN, weight=BOLD)
        demo.shift(UP * 1.5)

        # Glow effect
        demo_glow = demo.copy().set_opacity(0.15).scale(1.05)

        self.play(FadeIn(demo_glow), Write(demo, run_time=1.5))

        # Feature highlights
        features = VGroup(
            section_badge("3D Globe", ACCENT_BLUE),
            section_badge("Shodan Search", ACCENT_PURPLE),
            section_badge("Live Attack", SEVERITY_CRITICAL),
            section_badge("Range Monitor", ACCENT_GREEN),
            section_badge("Risk Scoring", ACCENT_AMBER),
        ).arrange(RIGHT, buff=0.3)
        features.shift(DOWN * 0.5)

        self.play(LaggedStart(
            *[FadeIn(f, scale=0.8) for f in features],
            lag_ratio=0.1
        ), run_time=1.5)

        # Bottom text
        bottom = VGroup(
            Text("AIMap", font="SF Mono", font_size=24, color=TEXT_PRIMARY, weight=BOLD),
            Text("Securing the Agentic Era", font="SF Mono", font_size=16, color=TEXT_MUTED),
        ).arrange(DOWN, buff=0.2)
        bottom.shift(DOWN * 2.5)

        self.play(FadeIn(bottom, shift=UP * 0.3))

        # Pulse the demo text
        self.play(
            demo.animate.scale(1.05),
            demo_glow.animate.scale(1.1).set_opacity(0.25),
            rate_func=there_and_back,
            run_time=1.5
        )
        self.play(
            demo.animate.scale(1.05),
            demo_glow.animate.scale(1.1).set_opacity(0.25),
            rate_func=there_and_back,
            run_time=1.5
        )

        self.wait(2)


# ═══════════════════════════════════════════════════════════════════════════════
# SLIDE 14: THANK YOU / CLOSE
# ═══════════════════════════════════════════════════════════════════════════════

class ThankYouSlide(Scene):
    def construct(self):
        # Background grid
        grid_lines = VGroup()
        for x in np.arange(-8, 8.5, 0.5):
            grid_lines.add(Line(
                [x, -5, 0], [x, 5, 0],
                stroke_color=BORDER, stroke_width=0.3, stroke_opacity=0.1
            ))
        for y in np.arange(-5, 5.5, 0.5):
            grid_lines.add(Line(
                [-8, y, 0], [8, y, 0],
                stroke_color=BORDER, stroke_width=0.3, stroke_opacity=0.1
            ))
        self.add(grid_lines)

        title = Text("AIMap", font="SF Mono", font_size=56, color=TEXT_PRIMARY, weight=BOLD)
        title.shift(UP * 2)

        tagline = Text("nmap for the Agentic Era", font="SF Mono", font_size=22, color=ACCENT_CYAN)
        tagline.next_to(title, DOWN, buff=0.3)

        underline = Line(
            tagline.get_left() + DOWN * 0.2,
            tagline.get_right() + DOWN * 0.2,
            color=ACCENT_BLUE, stroke_width=2, stroke_opacity=0.5
        )

        # Stats recap
        recap_items = [
            ("14+", "AI protocols", ACCENT_BLUE),
            ("3", "Attack engines", SEVERITY_CRITICAL),
            ("4", "Data sources", ACCENT_GREEN),
            ("3D", "Globe viz", ACCENT_PURPLE),
        ]

        recap = VGroup()
        for val, label, color in recap_items:
            v = Text(val, font="SF Mono", font_size=32, color=color, weight=BOLD)
            l = Text(label, font="SF Mono", font_size=12, color=TEXT_MUTED)
            item = VGroup(v, l).arrange(DOWN, buff=0.1)
            recap.add(item)

        recap.arrange(RIGHT, buff=1.5)
        recap.shift(DOWN * 0.5)

        # Thank you
        thanks = Text("Thank You", font="SF Mono", font_size=28, color=TEXT_MUTED)
        thanks.shift(DOWN * 2.5)

        built_with = Text(
            "Built with FastAPI + React + Globe.gl + MongoDB + Nuclei",
            font="SF Mono", font_size=12, color=BORDER
        )
        built_with.shift(DOWN * 3.3)

        self.play(Write(title, run_time=1.5))
        self.play(FadeIn(tagline, shift=UP * 0.2), Create(underline))
        self.play(LaggedStart(
            *[FadeIn(r, shift=UP * 0.3) for r in recap],
            lag_ratio=0.15
        ), run_time=1.5)
        self.play(FadeIn(thanks, shift=UP * 0.2), FadeIn(built_with, shift=UP * 0.1))

        self.wait(3)
