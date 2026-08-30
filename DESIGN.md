# CloudSentry Cyber-Ops Design System & Architecture Specification

> **Project Reference**: `CloudSentry SOC Dashboard` (`projects/13201866707050352871`)  
> **Aesthetic Philosophy**: Cyberpunk-Glassmorphic Tactical Security Operations Center (SOC)  
> **Target Audience**: Cloud Security Engineers, Threat Analysts, and SOC Operators  
> **Core Theme**: High-visibility neon signals on a deep, void-black (#0A0A0F) canvas with frosted glass panels and scan-line ambient textures.

---

## 1. Design Tokens & Color Palette

The color system is built upon a **Total Dark** foundation to eliminate eye strain in continuous 24/7 SOC monitoring environments while maximizing the cognitive impact of critical warning alerts.

### 1.1 Color Palette Matrix

| Token Name | Hex Code | Role & Usage |
| :--- | :--- | :--- |
| **`surface` / `background`** | `#111508` / `#0A0A0F` | Foundational void background canvas |
| **`surface-dim`** | `#111508` | Background baseline depth |
| **`surface-bright`** | `#373b2c` | Elevated card highlight |
| **`surface-container-lowest`**| `#0c0f04` | Deepest recessed panel background (e.g. SideNav base) |
| **`surface-container-low`** | `#191d10` | Subtle background for nested panels |
| **`surface-container`** | `#1d2113` | Standard structural container fill |
| **`surface-container-high`** | `#282c1d` | Hover states, active input containers |
| **`surface-container-highest`**| `#333627` | Highest contrast component fills |
| **`primary`** | `#ffffff` | Primary high-contrast text and major headers |
| **`primary-fixed`** | `#bef500` | **Neon Lime**: Safe states, system health, active highlights |
| **`primary-fixed-dim`** | `#a6d700` | Dimmed neon lime for secondary indicators |
| **`on-primary-fixed`** | `#151f00` | Text/icon color rendered on top of Neon Lime fills |
| **`primary-container`** | `#bef500` | Button and active nav pill fill background |
| **`on-primary-container`** | `#536d00` | High-contrast dark green text inside primary containers |
| **`secondary`** | `#ffb0cd` | Light neon pink text and secondary warning tags |
| **`secondary-container`** | `#e00088` / `#FF2E9F` | **Neon Hot Pink**: Critical alerts, intrusions, severe risks |
| **`on-secondary`** | `#640039` | Text on secondary elements |
| **`tertiary-fixed`** | `#d0e6f5` | Icy Cyan/Blue: Informational states and orphaned role metrics |
| **`error`** | `#ffb4ab` | High-visibility warning text for failed audits & expired keys |
| **`error-container`** | `#93000a` | Deep crimson alert containers |
| **`outline`** | `#8d9479` | Standard structural border lines |
| **`outline-variant`** | `#434933` | Subtle glass panel borders (1px translucent edges) |
| **`on-surface`** | `#e1e4cf` | Primary body typography color |
| **`on-surface-variant`** | `#c3caac` | Muted secondary labels, timestamps, metadata |

---

## 2. Typography System

The typography is structured for rapid cognitive intake and military-grade precision:

```
Fonts:
├── Syne        -> Brand headers, major screen titles, and section headlines
├── Bebas Neue  -> Large metrics, counters, and high-impact numerical telemetry
├── Oswald      -> Metadata tags, badges, table headers, and all-caps labels
└── Fira Sans   -> Body text, log outputs, data tables, and AI conversation streams
```

### 2.1 Type Scale Specification

| Role | Font Family | Size | Weight | Line Height | Letter Spacing | CSS Utility / Tailwind |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Display Hero** | `Syne` | `48px` | 800 | 1.1 | `-0.02em` | `font-display-hero text-display-hero` |
| **Metric Large** | `Bebas Neue` | `64px` | 400 | 1.0 | `+0.05em` | `font-metric-lg text-metric-lg` |
| **Metric Medium**| `Bebas Neue` | `32px` | 400 | 1.0 | `0.0em` | `font-metric-md text-metric-md` |
| **Headline Small**| `Syne` | `20px` | 700 | 1.4 | `0.0em` | `font-headline-sm text-headline-sm` |
| **Body Medium** | `Fira Sans` | `16px` | 400 | 1.6 | `0.0em` | `font-body-md text-body-md` |
| **Label Caps** | `Oswald` | `12px` | 500 | 1.0 | `+0.1em` | `font-label-caps text-label-caps uppercase` |
| **Code / ARN** | `JetBrains Mono` / `Fira Code` | `13px` | 500 | 1.4 | `0.0em` | `font-mono text-sm` |

---

## 3. Elevation, Glassmorphism & Atmospheric Effects

### 3.1 Depth Hierarchy
1. **Level 0 (Floor)**: Void Black `#0A0A0F` with global 4px CRT scan lines at 20% opacity.
2. **Level 1 (Panels & Cards)**: Glassmorphic containers with `rgba(25, 29, 16, 0.4)` background, `backdrop-blur: 12px`, and `1px solid rgba(255, 255, 255, 0.1)` border.
3. **Level 2 (Active Alerts / Critical Nodes)**: Neon outer bloom `box-shadow: 0 0 15px rgba(255, 46, 159, 0.4)` with 1px Neon Pink border.
4. **Level 3 (Modal / Overlays / Active Nav)**: `backdrop-blur: 24px` with high-luminance Neon Lime accent glow `box-shadow: 0 0 20px rgba(166, 215, 0, 0.4)`.

### 3.2 Atmospheric Glow Utilities
```css
/* Neon Bloom Effects */
.glow-lime {
  box-shadow: 0 0 15px rgba(198, 255, 0, 0.4);
  border: 1px solid rgba(198, 255, 0, 0.5);
}

.glow-pink {
  box-shadow: 0 0 15px rgba(255, 46, 159, 0.4);
  border: 1px solid rgba(255, 46, 159, 0.5);
}

.glow-text-lime {
  text-shadow: 0 0 10px rgba(190, 245, 0, 0.8);
}

.cyber-scan-lines {
  background: linear-gradient(
    to bottom,
    rgba(255, 255, 255, 0),
    rgba(255, 255, 255, 0) 50%,
    rgba(0, 0, 0, 0.2) 50%,
    rgba(0, 0, 0, 0.2)
  );
  background-size: 100% 4px;
  pointer-events: none;
}
```

---

## 4. Spacing & Grid System

- **Base Unit**: `4px`
- **Gutter**: `24px`
- **Desktop Margin**: `32px`
- **Mobile Margin**: `16px`
- **Max Container Width**: `1800px`
- **Navigation Width**: `288px` (`w-72`) fixed left sidebar

---

## 5. Screen Layouts & Component Patterns

The CloudSentry SOC project consists of **4 core screens**:

```
CloudSentry SOC Application
├── 1. Overview & Privilege Escalation Dashboard (Screen ID: bc7b98b20ffb45308a7c4a2ac5ed70b7)
├── 2. Least-Privilege Drift Analyzer (Screen ID: b3569d5f7d5e4594838d1853aa07a60d)
├── 3. Credential Hygiene & Posture Checker (Screen ID: c285d28b8c97476585f86b6d26711bbc)
└── 4. AI Security Assistant - SentryAI / NIMORA (Screen ID: 2e4b045dc37f4210971a2edf7b791f51)
```

---

### Screen 1: Overview & Privilege Escalation Dashboard
*Screen ID: `bc7b98b20ffb45308a7c4a2ac5ed70b7`*

```
+---------------------------------------------------------------------------------------------------+
| [SideNav: CloudSentry SOC] | TopBar: Search [________________] | Last Refreshed: 2m | [Avatar]    |
| - Privilege Escalation (*) |----------------------------------------------------------------------|
| - Privilege Drift          | Overview: Real-time threat telemetry and risk assessment   [Filter] [Export]
| - Credential Hygiene       |----------------------------------------------------------------------|
| - AI Assistant             | [ Total Events ]  [ Critical (12) ]  [ High Risk (48) ]  [ Medium (156) ] |
|                            |   1,284 (+12%)       (Pink Glow)        (Pink Glow)         (Lime Glow)   |
| [ Initialize Scan Button ] |----------------------------------------------------------------------|
|                            | Recent Risk Findings Table:                                          |
|                            | Timestamp | Identity | Resource ARN | Risk Type Badge | Status (Pulse)   |
+---------------------------------------------------------------------------------------------------+
```

#### Key Components:
1. **SideNavBar**: Fixed `288px` panel with Cyberpunk Operator avatar, threat level indicator ("Threat Level: High"), navigation links with neon lime active state pill (`bg-primary-container text-on-primary-container border-l-4 border-primary-fixed`), and radar scan trigger button.
2. **TopNavBar**: Glassmorphic sticky header (`bg-surface/60 backdrop-blur-xl`) with search field, live refresh indicator, notification icon, and security analyst profile image.
3. **Bento Metric Cards (4-Column Grid)**:
   - **Total Events**: `1,284` in `Bebas Neue` font with `+12%` delta indicator.
   - **Critical Events (Pink Glow)**: `12` with pulsing warning icon and `Immediate Action Required` tag.
   - **High Risk (Pink Glow)**: `48` with security shield icon and `+4 new` delta.
   - **Medium Risk (Lime Glow)**: `156` with stable state indicator.
4. **Recent Findings Table**:
   - `label-caps` all-caps header with Neon Lime underline (`border-b-2 border-primary-fixed`).
   - High-contrast risk badges: Solid Neon Pink (`bg-[#FF2E9F] text-black font-label-caps`) for Critical escalation; outline badges for Medium/Low.
   - Live status indicator: Pulsing pink dot `<span class="w-2 h-2 rounded-full bg-[#FF2E9F] animate-pulse"></span>`.

---

### Screen 2: Least-Privilege Drift Analyzer
*Screen ID: `b3569d5f7d5e4594838d1853aa07a60d`*

```
+---------------------------------------------------------------------------------------------------+
| [SideNav]                  | TopBar: Search [________________] | Last Refreshed: 2m | [Avatar]    |
|                            |----------------------------------------------------------------------|
|                            | Least-Privilege Drift Analyzer             [Remediate All Drift CTA] |
|                            | Continuous monitoring of IAM policies against actual usage patterns  |
|                            |----------------------------------------------------------------------|
|                            | [ Total Unused: 4,281 ]  [ High Risk Identities: 142 (Progress: 35%) ]|
|                            |   (Neon Top Accent Bar)  [ Orphaned Roles: 38        (Progress: 15%) ]|
|                            |----------------------------------------------------------------------|
|                            | Granted-But-Not-Used Audit Log:                                      |
|                            | IAM Role / Identity | Permission Action | Last Used | Risk | [Revoke]    |
+---------------------------------------------------------------------------------------------------+
```

#### Key Components:
1. **Hero Header & Global CTA**: Bold display title with "Remediate All Drift" action button in solid Neon Lime (`bg-primary-fixed text-on-primary-fixed hover:shadow-[0_0_20px_rgba(190,245,0,0.6)]`).
2. **Primary Metric Card**: Featured 4-column card with a top glowing neon line (`h-1 bg-primary-fixed shadow-[0_0_10px_rgba(190,245,0,0.8)]`), displaying `4,281` unused permissions and a `+12%` surge flag.
3. **Secondary Progress Cards (8-Column Subgrid)**:
   - **High Risk Identities**: Value `142` with 35% pink glow progress bar.
   - **Orphaned Roles**: Value `38` with 15% cyan progress bar.
4. **Granted-But-Not-Used Table**:
   - Monospace ARNs (`arn:aws:iam::prod:role/db-admin-legacy`).
   - Specific API action identifiers (`rds:DeleteDBInstance`, `storage.buckets.delete`).
   - Relative last-used badges (`Never`, `182d ago`).
   - **Hover Action**: Interactive "Revoke" button (`opacity-0 group-hover:opacity-100`) appearing smoothly on table row hover.

---

### Screen 3: Credential Hygiene & Posture Checker
*Screen ID: `c285d28b8c97476585f86b6d26711bbc`*

```
+---------------------------------------------------------------------------------------------------+
| [SideNav]                  | TopBar: Search [________________] | Last Refreshed: 2m | [Avatar]    |
|                            |----------------------------------------------------------------------|
|                            | Credential Hygiene: Audit access keys, passwords, and MFA            |
|                            |----------------------------------------------------------------------|
|                            | [ Circular SVG Gauge ] [ Stale Keys: 14 ] [ No MFA: 3 ] [ Pass: 2 ]  |
|                            |     Health: 78/100     (>90d - Pink)     (Critical-Lime) (Weak-Pink) |
|                            |----------------------------------------------------------------------|
|                            | Audited Identities Table (9-Cols)         | Quick Actions Panel (3-C)|
|                            | Identity | MFA Status | Last Key Rotation | [Rotate Stale Keys >]    |
|                            | Risk Score Badge (Critical/High/Low)      | [Enforce MFA >]          |
|                            |                                           | [Export Audit Report]    |
+---------------------------------------------------------------------------------------------------+
```

#### Key Components:
1. **Circular SVG Health Gauge**: Radial progress meter with animated SVG stroke-dasharray, neon lime glow, and centered `78 / 100` score in `Bebas Neue`.
2. **Trio Metric Cards**:
   - **Stale Access Keys**: Count `14` with `key_off` icon and pink side border.
   - **Users Without MFA**: Count `3` with `gpp_bad` icon and neon lime warning.
   - **Weak Password Policies**: Count `2` with `policy` icon.
3. **Audited Identities Table (9 Columns)**: Lists deployment service accounts, developer users, and API gateways with MFA status pills (`Disabled`, `Active`, `N/A`) and risk score badges.
4. **Quick Action Panel (3 Columns)**: Floating action sidebar with interactive buttons:
   - "Rotate Stale Keys" (`border-error/50 bg-error/10 hover:bg-error`).
   - "Enforce MFA" (`border-primary-fixed/50 bg-primary-fixed/10 hover:bg-primary-fixed`).
   - "Export Audit Report" button.

---

### Screen 4: AI Security Assistant (SentryAI / NIMORA)
*Screen ID: `2e4b045dc37f4210971a2edf7b791f51`*

```
+---------------------------------------------------------------------------------------------------+
| [SideNav]                  | TopBar: CloudSentry [Blur] | Query Logs [____] | Analyst Avatar      |
|----------------------------+----------------------------------------------------------------------|
| [ Active Analysis Context ]| SentryAI Unit Online (Pulsing Indicator)                             |
| Target Entity:             |----------------------------------------------------------------------|
|   arn:aws:iam::...:role    | (AI Bubble - Lime Left Border)                                       |
| Detected Anomaly:          | "Analyzing privilege drift in 'Prod-IAM-Role'..."                    |
|   Elevated beyond baseline | [Approve Remediate] [View Details]                                   |
| Duration: 4h 12m           |----------------------------------------------------------------------|
| Related Events Stream:     | (User Bubble - Pink Right Border)                                    |
|   - AssumeRole (10:42 AM)  | "Show me the affected resources first."                              |
|   - AttachRolePolicy       |----------------------------------------------------------------------|
|                            | [*] SentryAI is querying resources... (Typing Indicator)             |
|                            |----------------------------------------------------------------------|
|                            | [ + ] [ Command SentryAI or ask a question...               ] [SEND] |
+---------------------------------------------------------------------------------------------------+
```

#### Key Components:
1. **Left Context Rail (`w-80`)**: Dedicated drawer displaying the target ARN under investigation, detected anomaly tags, duration badges, and related CloudTrail event timeline entries.
2. **Chat Header**: Displays live connection status with pulsing neon dot: `<div class="w-3 h-3 rounded-full bg-primary-fixed animate-pulse neon-glow-primary"></div>`.
3. **AI Message Bubble**:
   - Glassmorphic card with a thick Neon Lime left border (`border-l-2 border-l-primary-fixed`).
   - Cyber-assistant bot avatar with neon green glow.
   - Interactive inline action chips: `Approve Remediate` and `View Details`.
4. **User Message Bubble**: Right-aligned conversation bubble with Neon Pink right accent border (`border-r-2 border-r-secondary-container`).
5. **Cyber Terminal Input Bar**:
   - Command input with monospace font and attachment icon.
   - Dedicated "SEND" button with Neon Lime border and hover state.
   - Disclaimer footer in `label-caps` 10px text.

---

## 6. Shared Component Specifications

### 6.1 Buttons
- **Primary Action**: `bg-primary-fixed text-on-primary-fixed hover:bg-primary font-label-caps uppercase tracking-wider rounded`
- **Ghost/Outline**: `border border-outline-variant text-on-surface hover:bg-surface-variant font-label-caps uppercase`
- **Destructive/Critical**: `border border-error/50 bg-error/10 text-error hover:bg-error hover:text-on-error font-label-caps uppercase`

### 6.2 Status Badges
- **Critical Risk**: Solid `#FF2E9F` background with `#000000` text + drop shadow glow.
- **High Risk**: Translucent pink background with `#FF2E9F` border and text.
- **Medium Risk**: Translucent lime background with `#BEF500` border and text.
- **Low Risk**: Translucent dim lime with `#A6D700` border and text.

### 6.3 Data Tables
- Header row with `border-b-2 border-primary-fixed` and uppercase `label-caps` tracking.
- Subtle row hover with neon lime tint: `hover:bg-primary-fixed/5`.
- Monospace font for technical identifiers, hashes, and ARNs.
