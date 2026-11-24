/**
 * Device type parsing and display names.
 *
 * Bitwarden clients are inconsistent: iOS sends the literal string `"iOS"`
 * while most others send a number. Both forms are accepted, and anything
 * invalid falls back to `Unknown Browser` (14), matching `models/device.rs`.
 */

export const DEVICE_TYPE = {
  Android: 0,
  Ios: 1,
  ChromeExtension: 2,
  FirefoxExtension: 3,
  OperaExtension: 4,
  EdgeExtension: 5,
  WindowsDesktop: 6,
  MacOsDesktop: 7,
  LinuxDesktop: 8,
  ChromeBrowser: 9,
  FirefoxBrowser: 10,
  OperaBrowser: 11,
  EdgeBrowser: 12,
  IEBrowser: 13,
  UnknownBrowser: 14,
  AndroidAmazon: 15,
  Uwp: 16,
  SafariBrowser: 17,
  VivaldiBrowser: 18,
  VivaldiExtension: 19,
  SafariExtension: 20,
  Sdk: 21,
  Server: 22,
  WindowsCli: 23,
  MacOsCli: 24,
  LinuxCli: 25,
  DuckDuckGoBrowser: 26,
} as const;

const DISPLAY_NAMES: Readonly<Record<number, string>> = {
  0: 'Android',
  1: 'iOS',
  2: 'Chrome Extension',
  3: 'Firefox Extension',
  4: 'Opera Extension',
  5: 'Edge Extension',
  6: 'Windows',
  7: 'macOS',
  8: 'Linux',
  9: 'Chrome',
  10: 'Firefox',
  11: 'Opera',
  12: 'Edge',
  13: 'Internet Explorer',
  14: 'Unknown Browser',
  15: 'Android',
  16: 'UWP',
  17: 'Safari',
  18: 'Vivaldi',
  19: 'Vivaldi Extension',
  20: 'Safari Extension',
  21: 'SDK',
  22: 'Server',
  23: 'Windows CLI',
  24: 'macOS CLI',
  25: 'Linux CLI',
  26: 'DuckDuckGo',
};

const NAME_TO_TYPE: Readonly<Record<string, number>> = {
  android: DEVICE_TYPE.Android,
  ios: DEVICE_TYPE.Ios,
  'chrome extension': DEVICE_TYPE.ChromeExtension,
  'firefox extension': DEVICE_TYPE.FirefoxExtension,
  'opera extension': DEVICE_TYPE.OperaExtension,
  'edge extension': DEVICE_TYPE.EdgeExtension,
  windows: DEVICE_TYPE.WindowsDesktop,
  'windows desktop': DEVICE_TYPE.WindowsDesktop,
  macos: DEVICE_TYPE.MacOsDesktop,
  'macos desktop': DEVICE_TYPE.MacOsDesktop,
  linux: DEVICE_TYPE.LinuxDesktop,
  'linux desktop': DEVICE_TYPE.LinuxDesktop,
  chrome: DEVICE_TYPE.ChromeBrowser,
  firefox: DEVICE_TYPE.FirefoxBrowser,
  opera: DEVICE_TYPE.OperaBrowser,
  edge: DEVICE_TYPE.EdgeBrowser,
  'internet explorer': DEVICE_TYPE.IEBrowser,
  ie: DEVICE_TYPE.IEBrowser,
  'unknown browser': DEVICE_TYPE.UnknownBrowser,
  uwp: DEVICE_TYPE.Uwp,
  safari: DEVICE_TYPE.SafariBrowser,
  vivaldi: DEVICE_TYPE.VivaldiBrowser,
  'vivaldi extension': DEVICE_TYPE.VivaldiExtension,
  'safari extension': DEVICE_TYPE.SafariExtension,
  sdk: DEVICE_TYPE.Sdk,
  server: DEVICE_TYPE.Server,
  'windows cli': DEVICE_TYPE.WindowsCli,
  'macos cli': DEVICE_TYPE.MacOsCli,
  'linux cli': DEVICE_TYPE.LinuxCli,
  duckduckgo: DEVICE_TYPE.DuckDuckGoBrowser,
};

/** Strict parse: `null` when the value is empty, unknown or out of range. */
export function parseDeviceType(raw: string): number | null {
  const trimmed = raw.trim();
  if (trimmed.length === 0) return null;

  if (/^-?\d+$/.test(trimmed)) {
    const value = Number.parseInt(trimmed, 10);
    return DISPLAY_NAMES[value] === undefined ? null : value;
  }

  return NAME_TO_TYPE[trimmed.toLowerCase()] ?? null;
}

/** Lenient parse used at the call sites: invalid input becomes `Unknown Browser`. */
export function deviceTypeFromString(raw: string): number {
  return parseDeviceType(raw) ?? DEVICE_TYPE.UnknownBrowser;
}

/** Display name used for the `devicetype` JWT claim and device listings. */
export function deviceTypeDisplayName(value: number): string {
  return DISPLAY_NAMES[value] ?? 'Unknown Browser';
}

/** Devices that can receive mobile push notifications. */
export function isPushDevice(value: number): boolean {
  return value === DEVICE_TYPE.Android || value === DEVICE_TYPE.Ios;
}
