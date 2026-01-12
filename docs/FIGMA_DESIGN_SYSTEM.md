# Figma Design System Specification
## NetFlow Analytics Dashboard - Premium Cyberpunk Operations Console

**Version**: 3.0  
**Last Updated**: 2026-01-12  
**Purpose**: Complete design system specification for recreating the dashboard design in Figma

---

## 🎨 Color Palette

### Base Colors
| Variable | Hex Value | Usage |
|----------|-----------|-------|
| `--bg-primary` | `#0d0d0d` | Near-black base (darker) |
| `--bg-secondary` | `#111111` | Slightly lighter for depth |
| `--bg-elevated` | `#1a1a1a` | Cards and elevated surfaces (darker) |
| `--bg-overlay` | `rgba(5, 5, 5, 0.98)` | Overlays and modals (darker) |

### Glass Morphism
| Variable | Value | Usage |
|----------|-------|-------|
| `--glass-bg` | `rgba(255, 255, 255, 0.06)` | Glass background |
| `--glass-bg-hover` | `rgba(255, 255, 255, 0.09)` | Glass hover state |
| `--glass-border` | `rgba(0, 243, 255, 0.15)` | Glass border |
| `--glass-border-hover` | `rgba(0, 243, 255, 0.25)` | Glass border hover |
| `--glass-blur` | `16px` | Backdrop blur amount |

### Card System
| Variable | Value | Usage |
|----------|-------|-------|
| `--card-bg` | `rgba(20, 20, 20, 0.7)` | Card background |
| `--card-bg-hover` | `rgba(25, 25, 25, 0.8)` | Card hover background |
| `--card-border` | `rgba(0, 243, 255, 0.12)` | Card border |
| `--card-border-hover` | `rgba(0, 243, 255, 0.2)` | Card border hover |

### Accent Colors (Functional)
| Variable | Hex Value | Usage |
|----------|-----------|-------|
| `--accent-primary` | `#00f3ff` | Cyan - Primary actions, highlights |
| `--accent-primary-hover` | `#00d4e6` | Cyan hover state |
| `--accent-secondary` | `#ff00ff` | Magenta - Secondary actions, warnings |
| `--accent-secondary-hover` | `#cc00cc` | Magenta hover state |
| `--accent-danger` | `#ff003c` | Red - Critical alerts, errors |
| `--accent-danger-hover` | `#cc002e` | Red hover state |
| `--accent-success` | `#00ff88` | Green - Success states, health |
| `--accent-success-hover` | `#00cc6a` | Green hover state |
| `--accent-warning` | `#ffb800` | Amber - Warnings |
| `--accent-warning-hover` | `#cc9300` | Amber hover state |

### Text Colors
| Variable | Hex Value | Usage |
|----------|-----------|-------|
| `--text-primary` | `#e8e8e8` | Main content - WCAG AAA on bg-primary |
| `--text-secondary` | `#a0a0a0` | Secondary content - WCAG AA |
| `--text-tertiary` | `#707070` | Tertiary, disabled states |
| `--text-muted` | `#666666` | Muted text |
| `--text-inverse` | `#000000` | Text on accent backgrounds |
| `--text-light` | `#f5f5f5` | Light text for emphasis |

---

## 📝 Typography

### Font Families
- **Sans-serif (UI)**: `'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`
- **Monospace (Data)**: `'JetBrains Mono', 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, monospace`

### Typography Scale (Modular scale - 1.125 ratio, 16px base)
| Variable | Size (rem) | Size (px) | Usage |
|----------|------------|-----------|-------|
| `--text-xs` | `0.75rem` | `12px` | Captions, labels |
| `--text-sm` | `0.875rem` | `14px` | Secondary text |
| `--text-base` | `1rem` | `16px` | Body text |
| `--text-lg` | `1.125rem` | `18px` | Emphasized body |
| `--text-xl` | `1.25rem` | `20px` | Small headings |
| `--text-2xl` | `1.5rem` | `24px` | Section titles |
| `--text-3xl` | `1.875rem` | `30px` | Page titles |
| `--text-4xl` | `2.25rem` | `36px` | Hero text |

### Font Weights
- `--font-weight-normal`: `400`
- `--font-weight-medium`: `500`
- `--font-weight-semibold`: `600`
- `--font-weight-bold`: `700`
- `--font-weight-extrabold`: `800`

### Letter Spacing
- `--letter-spacing-tight`: `-0.02em`
- `--letter-spacing-normal`: `0`
- `--letter-spacing-wide`: `0.02em`
- `--letter-spacing-wider`: `0.05em`
- `--letter-spacing-widest`: `0.1em`

### Line Heights
- `--line-height-tight`: `1.25`
- `--line-height-normal`: `1.5`
- `--line-height-relaxed`: `1.75`

---

## 📐 Spacing System (8px base unit)

| Variable | Size (rem) | Size (px) | Usage |
|----------|------------|-----------|-------|
| `--space-0` | `0` | `0px` | No spacing |
| `--space-1` | `0.25rem` | `4px` | Tight spacing |
| `--space-2` | `0.5rem` | `8px` | Small spacing |
| `--space-3` | `0.75rem` | `12px` | Medium-small spacing |
| `--space-4` | `1rem` | `16px` | Base spacing unit |
| `--space-5` | `1.25rem` | `20px` | Medium spacing |
| `--space-6` | `1.5rem` | `24px` | Large spacing |
| `--space-8` | `2rem` | `32px` | Extra large spacing |
| `--space-12` | `3rem` | `48px` | Section spacing |
| `--space-16` | `4rem` | `64px` | Major section spacing |
| `--space-24` | `6rem` | `96px` | Maximum spacing |

---

## 🔲 Border Radius

| Variable | Value | Usage |
|----------|-------|-------|
| `--radius-none` | `0` | Sharp corners |
| `--radius-sm` | `4px` | Small rounded corners |
| `--radius-md` | `6px` | Medium rounded corners |
| `--radius-lg` | `8px` | Large rounded corners |
| `--radius-xl` | `12px` | Extra large rounded corners |
| `--radius-2xl` | `16px` | Very large rounded corners |
| `--radius-full` | `9999px` | Fully rounded (pills, circles) |

---

## 🌟 Shadows & Effects

### Standard Shadows
| Variable | Value | Usage |
|----------|-------|-------|
| `--shadow-sm` | `0 2px 4px rgba(0, 0, 0, 0.4), 0 1px 2px rgba(0, 0, 0, 0.3)` | Small elevation |
| `--shadow-md` | `0 4px 8px rgba(0, 0, 0, 0.5), 0 2px 4px rgba(0, 0, 0, 0.4)` | Medium elevation |
| `--shadow-lg` | `0 8px 16px rgba(0, 0, 0, 0.6), 0 4px 8px rgba(0, 0, 0, 0.5)` | Large elevation |
| `--shadow-xl` | `0 12px 24px rgba(0, 0, 0, 0.7), 0 6px 12px rgba(0, 0, 0, 0.6)` | Extra large elevation |
| `--shadow-2xl` | `0 16px 32px rgba(0, 0, 0, 0.8), 0 8px 16px rgba(0, 0, 0, 0.7)` | Maximum elevation |

### Glass Shadows
| Variable | Value | Usage |
|----------|-------|-------|
| `--glass-shadow` | `0 12px 48px rgba(0, 0, 0, 0.6), 0 0 0 1px rgba(0, 243, 255, 0.1)` | Glass card shadow |
| `--glass-shadow-hover` | `0 16px 64px rgba(0, 0, 0, 0.7), 0 0 20px rgba(0, 243, 255, 0.15)` | Glass card hover shadow |

### Card Shadows
| Variable | Value | Usage |
|----------|-------|-------|
| `--card-shadow` | `0 8px 32px rgba(0, 0, 0, 0.5), 0 2px 8px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.05)` | Standard card shadow |
| `--card-shadow-hover` | `0 12px 48px rgba(0, 0, 0, 0.6), 0 4px 16px rgba(0, 0, 0, 0.4), 0 0 24px rgba(0, 243, 255, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.08)` | Card hover shadow |

### Glow Effects
| Variable | Value | Usage |
|----------|-------|-------|
| `--shadow-glow-primary` | `0 0 8px rgba(0, 243, 255, 0.15), 0 0 16px rgba(0, 243, 255, 0.25)` | Cyan glow |
| `--shadow-glow-danger` | `0 0 8px rgba(255, 0, 60, 0.2), 0 0 16px rgba(255, 0, 60, 0.3)` | Red glow |
| `--shadow-glow-secondary` | `0 0 8px rgba(255, 0, 255, 0.12), 0 0 16px rgba(255, 0, 255, 0.25)` | Magenta glow |

---

## ⚡ Transitions & Motion

| Variable | Value | Usage |
|----------|-------|-------|
| `--motion-fast` | `150ms cubic-bezier(0.4, 0, 0.2, 1)` | Fast transitions (hover states) |
| `--motion-base` | `200ms cubic-bezier(0.4, 0, 0.2, 1)` | Standard transitions |
| `--motion-slow` | `300ms cubic-bezier(0.4, 0, 0.2, 1)` | Slow transitions (modals) |
| `--motion-bounce` | `cubic-bezier(0.68, -0.55, 0.265, 1.55)` | Bouncy animations |

---

## 📐 Layout Constraints

| Variable | Value | Usage |
|----------|-------|-------|
| `--container-max-width` | `1920px` | Maximum container width |
| `--container-padding` | `var(--space-4)` | Container padding (16px) |
| `--header-height` | `64px` | Header height (sticky) |
| `--status-bar-height` | `40px` | Status bar height (sticky bottom) |
| `--sidebar-width` | `280px` | Sidebar width (desktop) |

---

## 🎯 Z-Index Scale

| Variable | Value | Usage |
|----------|-------|-------|
| `--z-base` | `0` | Base layer |
| `--z-elevated` | `10` | Elevated cards |
| `--z-dropdown` | `100` | Dropdown menus |
| `--z-sticky` | `200` | Sticky elements (header, sidebar) |
| `--z-modal-backdrop` | `900` | Modal backdrop |
| `--z-modal` | `1000` | Modal content |
| `--z-tooltip` | `1100` | Tooltips |
| `--z-notification` | `1200` | Notifications |

---

## 🏗️ Layout Structure

### Header (Sticky, 64px height)
- **Background**: `--bg-elevated` with glass effect
- **Border**: Bottom border with `--glass-border`
- **Layout**: Flexbox (horizontal)
- **Left**: Logo/Branding
- **Center**: Primary navigation tabs (Overview, Security, Network, Forensics, Server)
- **Right**: Global controls (Time range selector, search input, settings button)

### Navigation Tabs
- **Active state**: `--accent-primary` underline or background
- **Inactive state**: `--text-secondary`
- **Hover state**: `--text-primary` with subtle background
- **Padding**: `--space-3` (12px) horizontal, `--space-2` (8px) vertical
- **Font**: `--font-sans`, `--text-base` (16px), `--font-weight-medium` (500)

### Sidebar (Desktop, 280px width)
- **Background**: `--bg-elevated` with glass effect
- **Border**: Right border with `--glass-border`
- **Padding**: `--space-4` (16px)
- **Scroll behavior**: Smooth scroll with custom scrollbar

### Content Area
- **Layout**: CSS Grid (responsive)
- **Gap**: `--space-4` (16px) between cards
- **Padding**: `--space-4` (16px) from container edges
- **Background**: `--bg-primary` with pixel grid pattern overlay

### Cards/Widgets
- **Background**: `--card-bg` with glass effect
- **Border**: `1px solid` `--card-border`
- **Border Radius**: `--radius-lg` (8px)
- **Shadow**: `--card-shadow`
- **Padding**: `--space-4` (16px)
- **Hover**: Enhanced shadow (`--card-shadow-hover`), border color change

### Status Bar (Sticky bottom, 40px height)
- **Background**: `--bg-elevated` with glass effect
- **Border**: Top border with `--glass-border`
- **Layout**: Flexbox (horizontal, space-between)
- **Content**: Key metrics, system status indicators, last update timestamp
- **Font**: `--font-mono`, `--text-sm` (14px)

---

## 📱 Responsive Breakpoints

| Breakpoint | Width | Description |
|------------|-------|-------------|
| Mobile | `320px - 767px` | Single column, bottom navigation |
| Tablet | `768px - 1023px` | Two columns, sidebar collapsed |
| Desktop | `1024px - 1919px` | Full layout with sidebar |
| Wide | `1920px+` | Maximum container width applied |

### Mobile-Specific
- **Bottom Navigation**: Fixed 5-button navigation bar
- **Header**: Collapsed with hamburger menu
- **Cards**: Full width, stacked vertically
- **Sidebar**: Hidden (accessible via menu)

---

## 🎨 Background Patterns

### Pixel Grid Pattern
- **Color**: `rgba(0, 243, 255, 0.02)` - Very subtle cyan
- **Size**: `20px × 20px` grid
- **Application**: Applied to body background

### Scanline Effect
- **Color**: `rgba(0, 0, 0, 0.1)` - Dark scanlines
- **Pattern**: Repeating vertical lines every 2px
- **Application**: Overlaid on body background for retro effect

---

## 🔘 Interactive Elements

### Buttons
- **Primary Button**:
  - Background: `--accent-primary`
  - Text: `--text-inverse` (black)
  - Border: `1px solid` `--accent-primary`
  - Border Radius: `--radius-sm` (4px)
  - Padding: `8px 16px`
  - Font: `--font-sans`, `--text-sm` (14px), `--font-weight-semibold` (600)
  - Shadow: `--shadow-sm`
  - Hover: Background `--accent-primary-hover`, enhanced shadow

- **Secondary Button**:
  - Background: `rgba(255, 255, 255, 0.03)`
  - Text: `--text-primary`
  - Border: `1px solid rgba(255, 255, 255, 0.08)`
  - Border Radius: `--radius-sm` (4px)
  - Padding: `8px 16px`
  - Hover: Background `rgba(255, 255, 255, 0.05)`, border `rgba(255, 255, 255, 0.1)`

- **Danger Button**:
  - Background: `rgba(255, 0, 60, 0.12)`
  - Text: `--accent-danger`
  - Border: `1px solid` `--accent-danger`
  - Hover: Background `rgba(255, 0, 60, 0.2)`, glow effect

### Input Fields
- **Background**: `rgba(255, 255, 255, 0.03)`
- **Border**: `1px solid rgba(255, 255, 255, 0.08)`
- **Border Radius**: `--radius-sm` (4px)
- **Padding**: `8px 12px`
- **Font**: `--font-sans`, `--text-base` (16px)
- **Focus**: Border `--accent-primary`, glow effect
- **Placeholder**: `--text-tertiary` (#707070)

### Links
- **Color**: `--accent-primary`
- **Text Decoration**: None
- **Hover**: `--accent-primary-hover`, underline
- **Focus**: Outline with `--accent-primary`

---

## 📊 Data Visualization

### Charts
- **Background**: Transparent (inherits card background)
- **Grid Lines**: `rgba(255, 255, 255, 0.05)`
- **Axes**: `--text-secondary` (#a0a0a0)
- **Data Colors**: Use accent colors (cyan, magenta, green, red, amber)

### Tables
- **Header Background**: `rgba(255, 255, 255, 0.03)`
- **Header Text**: `--text-secondary`, `--font-weight-semibold`
- **Row Background**: Transparent
- **Row Hover**: `rgba(255, 255, 255, 0.03)`
- **Border**: `1px solid rgba(255, 255, 255, 0.05)`
- **Cell Padding**: `--space-2` (8px) vertical, `--space-3` (12px) horizontal

### Progress Bars
- **Background**: `rgba(255, 255, 255, 0.05)`
- **Fill (Success)**: `--accent-success`
- **Fill (Warning)**: `--accent-warning`
- **Fill (Danger)**: `--accent-danger`
- **Height**: `4px` or `8px` depending on context
- **Border Radius**: `--radius-full` (fully rounded)

---

## 🎭 Component Examples

### Card Component
```
Container:
  - Background: var(--card-bg) with backdrop-filter blur(var(--glass-blur))
  - Border: 1px solid var(--card-border)
  - Border Radius: var(--radius-lg) (8px)
  - Padding: var(--space-4) (16px)
  - Shadow: var(--card-shadow)
  - Transition: var(--motion-base)

Header (optional):
  - Font: var(--font-sans), var(--text-xl) (20px), var(--font-weight-semibold)
  - Color: var(--text-primary)
  - Margin Bottom: var(--space-3) (12px)

Content:
  - Font: var(--font-sans), var(--text-base) (16px)
  - Color: var(--text-secondary)
  - Line Height: var(--line-height-normal) (1.5)

Hover State:
  - Shadow: var(--card-shadow-hover)
  - Border: var(--card-border-hover)
  - Background: var(--card-bg-hover)
```

### Stat Box Component
```
Container:
  - Same as Card Component
  - Display: Flex (column)
  - Alignment: Center

Value:
  - Font: var(--font-mono), var(--text-2xl) (24px), var(--font-weight-bold)
  - Color: var(--text-primary)

Label:
  - Font: var(--font-sans), var(--text-sm) (14px), var(--font-weight-medium)
  - Color: var(--text-secondary)
  - Margin Top: var(--space-1) (4px)
```

---

## 🎯 Implementation Notes for Figma

1. **Create Color Styles**: Define all color variables as Figma color styles
2. **Create Text Styles**: Define typography scale as Figma text styles
3. **Use Auto Layout**: Leverage Figma's Auto Layout for spacing consistency
4. **Effects Setup**:
   - Glass morphism: Use Figma's background blur effect
   - Shadows: Recreate layered shadows as multiple shadow effects
   - Glows: Use outer glow effects with appropriate opacity
5. **Grid System**: Set up a 20px grid for pixel-perfect alignment
6. **Components**: Create reusable card, button, and input components
7. **Variants**: Use component variants for hover/active states
8. **Responsive**: Create separate frames for mobile/tablet/desktop breakpoints

---

## 📋 Checklist for Figma Recreation

- [ ] Set up color styles (all CSS variables)
- [ ] Create text styles (typography scale)
- [ ] Define spacing system (8px base unit)
- [ ] Create card component with glass effect
- [ ] Create button components (primary, secondary, danger)
- [ ] Set up grid system (20px)
- [ ] Create header component
- [ ] Create sidebar component
- [ ] Create navigation tabs component
- [ ] Create status bar component
- [ ] Recreate background patterns
- [ ] Set up responsive frames
- [ ] Create widget/card variants
- [ ] Add hover states to interactive elements
- [ ] Test color contrast (WCAG AA/AAA)

---

## 🔗 Related Documentation

- [REDESIGN_PLAN.md](./REDESIGN_PLAN.md) - Original redesign plan
- [AGENTS.md](./AGENTS.md) - Architecture documentation
- `static/style.css` - Source CSS file with all variables
- `templates/index.html` - HTML structure reference

---

**Note**: This specification is based on the current CSS implementation (v3.0). When recreating in Figma, ensure all measurements and colors match exactly for pixel-perfect reproduction.
