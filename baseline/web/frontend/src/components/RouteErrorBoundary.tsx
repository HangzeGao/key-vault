import { Component, type ErrorInfo, type ReactNode } from "react";

export class RouteErrorBoundary extends Component<{ children: ReactNode }, { error?: Error }> {
  state: { error?: Error } = {};
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(error: Error, info: ErrorInfo) {
    // Do not serialize props, API responses, or secrets into telemetry.
    console.error("route render failed", { name: error.name, componentStack: info.componentStack });
  }
  render() {
    if (!this.state.error) return this.props.children;
    return <main className="page-container"><section className="route-error" role="alert"><h1>Page unavailable</h1><p>This route encountered an unexpected rendering error. Other areas of the vault remain available.</p><div className="toolbar-row"><button className="btn btn-primary" onClick={() => this.setState({ error: undefined })}>Try again</button><a className="btn btn-ghost" href="/ui/dashboard">Dashboard</a></div></section></main>;
  }
}
