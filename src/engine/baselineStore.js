class BehaviorBaseline {
  constructor() {
    this.routeStats = new Map();
    this.transitionStats = new Map();
    this.observationCount = 0;
  }

  observe(previousPath, features) {
    this.observationCount += 1;
    const route = this.routeStats.get(features.path) || {
      count: 0,
      avgPayloadSize: 0,
      avgEntropy: 0,
      avgPathDepth: features.pathDepth
    };

    route.count += 1;
    route.avgPayloadSize = movingAverage(route.avgPayloadSize, features.payloadSize, route.count);
    route.avgEntropy = movingAverage(route.avgEntropy, features.payloadEntropy, route.count);
    route.avgPathDepth = movingAverage(route.avgPathDepth, features.pathDepth, route.count);
    this.routeStats.set(features.path, route);

    if (previousPath) {
      if (!this.transitionStats.has(previousPath)) {
        this.transitionStats.set(previousPath, new Map());
      }
      const nextRoutes = this.transitionStats.get(previousPath);
      nextRoutes.set(features.path, (nextRoutes.get(features.path) || 0) + 1);
    }
  }

  getRouteStats(path) {
    return this.routeStats.get(path) || null;
  }

  hasRoute(path) {
    return this.routeStats.has(path);
  }

  hasTransition(fromPath, toPath) {
    if (!fromPath) return true;
    const nextRoutes = this.transitionStats.get(fromPath);
    if (!nextRoutes) return false;
    return nextRoutes.has(toPath);
  }

  snapshot() {
    return {
      observationCount: this.observationCount,
      routes: [...this.routeStats.entries()]
        .map(([path, stats]) => ({
          path,
          count: stats.count,
          avgPayloadSize: Number(stats.avgPayloadSize.toFixed(2)),
          avgEntropy: Number(stats.avgEntropy.toFixed(2)),
          avgPathDepth: Number(stats.avgPathDepth.toFixed(2))
        }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 12),
      transitions: [...this.transitionStats.entries()]
        .flatMap(([fromPath, nextRoutes]) =>
          [...nextRoutes.entries()].map(([toPath, count]) => ({ fromPath, toPath, count }))
        )
        .sort((a, b) => b.count - a.count)
        .slice(0, 12)
    };
  }
}

function movingAverage(previousAverage, nextValue, count) {
  if (count <= 1) return nextValue;
  return previousAverage + (nextValue - previousAverage) / count;
}

module.exports = { BehaviorBaseline };
