<?php

namespace OhSeeSoftware\LaravelServerAnalytics;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Jaybizzle\CrawlerDetect\CrawlerDetect;
use OhSeeSoftware\LaravelServerAnalytics\Models\Analytics;
use OhSeeSoftware\LaravelServerAnalytics\Models\AnalyticsBlockIp;
use Symfony\Component\HttpFoundation\Response;
use ipinfo\ipinfo\IPinfo;

class LaravelServerAnalytics
{
    /** @var array */
    public $excludeRoutes = [];

    public $excludeIps = [];

    /** @var array */
    public $excludeMethods = [];

    /** @var array */
    public $metaHooks = [];

    /** @var array */
    public $relationHooks = [];

    /**
     * Returns the class which represents users.
     */
    public static function getUserModel(): string
    {
        return config('laravel-server-analytics.user_model');
    }

    /**
     * Indicates if we should ignore requests from bots.
     */
    public static function shouldIgnoreBotRequests(): bool
    {
        return config('laravel-server-analytics.ignore_bot_requests');
    }


    /**
     * Returns the name of the analytics data table.
     */
    public static function getAnalyticsDataTable(): string
    {
        return config('laravel-server-analytics.analytics_data_table');
    }

    /**
     * Returns the name of the analytics relation table.
     */
    public static function getAnalyticsRelationTable(): string
    {
        return config('laravel-server-analytics.analytics_relation_table');
    }

    /**
     * Returns the name of the analytics meta table.
     */
    public static function getAnalyticsMetaTable(): string
    {
        return config('laravel-server-analytics.analytics_meta_table');
    }

    /**
     * Returns the FQN of the RequestDetails class to user.
     */
    public static function getRequestDetailsClass(): string
    {
        return config('laravel-server-analytics.request_details_class');
    }

    public static function getQueueConnection(): string|null
    {
        return config('laravel-server-analytics.queue_connection', null);
    }

    /**
     * Add routes to exclude from tracking.
     *
     * Routes can use wildcard matching.
     */
    public function addRouteExclusions(array $routes): void
    {
        $this->excludeRoutes = array_merge($this->excludeRoutes, $routes);
    }

    /**
     * Add routes to exclude from tracking.
     *
     * Routes can use wildcard matching.
     */
    public function addIpExclusions(array $ips): void
    {
        $this->excludeIps = array_merge($this->excludeIps, $ips);
    }

    /**
     * Add methods to exclude from tracking.
     */
    public function addMethodExclusions(array $methods): void
    {
        $methods = array_map(function ($method) {
            return strtoupper($method);
        }, $methods);

        $this->excludeMethods = array_merge($this->excludeMethods, $methods);
    }

    /**
     * Determine if the request should be tracked.
     */
    public function shouldTrackRequest(Request $request): bool
    {
        if (in_array($request->ip(), $this->excludeIps, true)) {
            return false;
        }

        if($this->isKnownBotIp($request->ip())) {
            return false;
        }

        if($this->checkIP($request->ip())) {
            return false;
        }

        if ($this->inExcludeRoutesArray($request) || $this->inExcludeMethodsArray($request)) {
            return false;
        }

        if (static::shouldIgnoreBotRequests() && (new CrawlerDetect())->isCrawler($request->userAgent())) {
            return false;
        }

        return true;
    }

    public function checkIP(string $ip) : bool {
        $ipinfo = new IPinfo();
        $details = $ipinfo->getDetails($ip);

        $asn = $details->asn ?? ($details->all["org"] ?? null);

// OVH ASNs
        $blockedAsns = [
            // OVH
            "AS16276",
            "AS35540",
            "AS43996",
            // AWS
            "AS16509",
            "AS14618",

            // Hetzner
            "AS24940",
            "AS213230",

            // OVH
            "AS16276",
            "AS35540",
            "AS43996",

            // DigitalOcean
            "AS14061",
            "AS200130",

            // Linode
            "AS63949",

            //microsoft
            "AS8075",
            "AS8068",
            "AS8069",
            "AS3598"
        ];

        $block = $asn &&
            (in_array($asn, $blockedAsns, true) ||
                !empty(array_filter($blockedAsns, static fn($n) => str_contains($asn, $n))));

        if($block) {
            AnalyticsBlockIp::query()->updateOrCreate([
                'ip' => $ip
            ]);
        }

        return $block;

    }

    function isKnownBotIp(string $ip): bool
    {
        $botCidrs = $this->getKnownBotRanges();

        foreach ($botCidrs as $cidr) {
            if ($this->ipInCidr($ip, $cidr)) {
                return true;
            }
        }

        $knownASNIp = AnalyticsBlockIp::query()->where('ip', $ip)->first();
        if ($knownASNIp) {
            return true;
        }

        return false;
    }

    function ipInCidr(string $ip, string $cidr): bool
    {
        if (str_contains($cidr, ':')) {
            // IPv6
            [$subnet, $mask] = explode('/', $cidr);
            $ipBinary     = inet_pton($ip);
            $subnetBinary = inet_pton($subnet);

            if ($ipBinary === false || $subnetBinary === false) {
                return false;
            }

            $maskBinary = str_repeat("\xff", $mask >> 3);
            if ($mask % 8) {
                $maskBinary .= chr(0xff << (8 - ($mask % 8)));
            }
            $maskBinary = str_pad($maskBinary, strlen($ipBinary), "\0");

            return ($ipBinary & $maskBinary) === ($subnetBinary & $maskBinary);
        }

        // IPv4
        [$subnet, $mask] = explode('/', $cidr);
        $ipLong     = ip2long($ip);
        $subnetLong = ip2long($subnet);
        $maskLong   = -1 << (32 - $mask);

        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
    }



    private function getKnownBotRanges(): array
    {
        return [
            // Googlebot
            '66.249.64.0/19',
            '64.233.160.0/19',
            '72.14.192.0/18',
            '74.125.0.0/16',
            '209.85.128.0/17',
            '216.239.32.0/19',

            // Bingbot
            '13.66.0.0/16',
            '13.67.0.0/16',
            '13.68.0.0/14',
            '40.77.167.0/24',
            '40.77.188.0/24',
            '52.167.0.0/16',

            // DuckDuckBot
            '20.191.45.212/32',
            '20.185.79.47/32',
            '40.88.21.235/32',
            '40.70.20.60/32',

            // YandexBot
            '5.255.252.0/24',
            '5.45.207.0/24',
            '37.9.64.0/18',
            '77.88.0.0/18',
            '84.201.146.0/24',

            // Baidu Spider
            '123.125.71.0/24',
            '180.76.15.0/24',
            '180.76.6.0/24',

            // AhrefsBot
            '54.36.148.0/24',
            '51.222.253.0/24',
            '167.94.138.0/24',
            '2a03:6f00:1::/48',

            // SemrushBot
            '46.229.168.0/24',
            '185.191.171.0/24',

            // Majestic / MJ12Bot
            '5.45.207.0/24',
            '37.235.48.0/24',
            '89.38.96.0/19',
        ];
    }

    /**
     * Add a hook for storing meta data with the Analytics record.
     *
     * The hook should return an array with `key` and `value` keys.
     */
    public function addMetaHook($callback): void
    {
        $this->metaHooks[] = $callback;
    }

    public function getMetaHooks(): array
    {
        return $this->metaHooks;
    }

    public function runMetaHooks(RequestDetails $requestDetails): array
    {
        return collect($this->metaHooks)
            ->map(function ($callback) use ($requestDetails) {
                return $callback($requestDetails);
            })
            ->toArray();
    }

    /**
     * Add a hook for storing meta data with the Analytics record.
     *
     * The hook should return an array with `model` and `reason` keys.
     */
    public function addRelationHook($callback): void
    {
        $this->relationHooks[] = $callback;
    }

    public function getRelationHooks(): array
    {
        return $this->relationHooks;
    }

    public function runRelationHooks(RequestDetails $requestDetails): array
    {
        return collect($this->relationHooks)
            ->map(function ($callback) use ($requestDetails) {
                return $callback($requestDetails);
            })
            ->toArray();
    }

    public function addRelation(Model $model, ?string $reason = null): void
    {
        $this->addRelationHook(function (RequestDetails $requestDetails) use ($model, $reason) {
            return [
                'model' => $model,
                'reason' => $reason,
            ];
        });
    }

    /**
     * Attaches the given meta to the current analytics record.
     */
    public function addMeta(string $key, $value): void
    {
        $this->addMetaHook(function (RequestDetails $requestDetails) use ($key, $value) {
            return [
                'key' => $key,
                'value' => $value,
            ];
        });
    }

    /**
     * Determine if the request should be excluded.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    public function inExcludeRoutesArray(Request $request): bool
    {
        foreach ($this->excludeRoutes as $route) {
            if ($route !== '/') {
                $route = trim($route, '/');
            }

            if ($request->fullUrlIs($route) || $request->is($route)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the request should be excluded.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    public function inExcludeMethodsArray(Request $request): bool
    {
        $method = strtoupper($request->method());
        return in_array($method, $this->excludeMethods);
    }
}
