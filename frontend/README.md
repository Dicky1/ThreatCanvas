# ThreatCanvas Frontend

React and TypeScript interface for creating attack scenarios, inspecting CIR
graphs, reviewing coverage and threat assessments, and comparing attack
simulations.

## Requirements

- A current Node.js LTS release
- The ThreatCanvas backend running at `http://127.0.0.1:8000`

## Local setup

Run these commands from `frontend/`:

```bash
npm ci
npm run dev
```

The development server runs at `http://localhost:5173`. Vite proxies relative
`/api` requests to the backend. Some existing clients use the backend's
`http://localhost:8000` URL directly, so both services must be available during
local development.

## Application structure

- `src/pages/` contains the routed dashboard, history, prompt library, login,
  and settings screens.
- `src/components/` contains graph, CIR, coverage, assessment, simulation, and
  layout views.
- `src/store/` contains Zustand stores for authentication, notifications, and
  threat-scenario state.
- `src/assets/` and `public/` contain static assets.

Routes other than `/login` are protected by the authentication route wrapper.

## Available commands

```bash
npm run dev      # start the Vite development server
npm run build    # type-check and create a production build
npm run lint     # run Oxlint
npm run preview  # preview the production build locally
```

Vitest and Testing Library are installed, but the current package scripts do
not define a test command.
