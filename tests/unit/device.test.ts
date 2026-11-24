import { describe, expect, it } from 'vitest';

import {
  DEVICE_TYPE,
  deviceTypeDisplayName,
  deviceTypeFromString,
  isPushDevice,
  parseDeviceType,
} from '../../src/auth/device';

describe('parseDeviceType', () => {
  it('accepts numeric values within the known range', () => {
    expect(parseDeviceType('0')).toBe(DEVICE_TYPE.Android);
    expect(parseDeviceType('14')).toBe(DEVICE_TYPE.UnknownBrowser);
    expect(parseDeviceType('26')).toBe(DEVICE_TYPE.DuckDuckGoBrowser);
    expect(parseDeviceType(' 9 ')).toBe(DEVICE_TYPE.ChromeBrowser);
  });

  it('rejects numbers outside the known range', () => {
    expect(parseDeviceType('27')).toBeNull();
    expect(parseDeviceType('-1')).toBeNull();
    expect(parseDeviceType('999')).toBeNull();
  });

  it('accepts the client-supplied names, case-insensitively', () => {
    expect(parseDeviceType('iOS')).toBe(DEVICE_TYPE.Ios);
    expect(parseDeviceType('ios')).toBe(DEVICE_TYPE.Ios);
    expect(parseDeviceType('Chrome Extension')).toBe(DEVICE_TYPE.ChromeExtension);
    expect(parseDeviceType('Windows')).toBe(DEVICE_TYPE.WindowsDesktop);
    expect(parseDeviceType('windows desktop')).toBe(DEVICE_TYPE.WindowsDesktop);
    expect(parseDeviceType('IE')).toBe(DEVICE_TYPE.IEBrowser);
    expect(parseDeviceType('DuckDuckGo')).toBe(DEVICE_TYPE.DuckDuckGoBrowser);
  });

  it('returns null for empty or unknown values', () => {
    expect(parseDeviceType('')).toBeNull();
    expect(parseDeviceType('   ')).toBeNull();
    expect(parseDeviceType('toaster')).toBeNull();
    expect(parseDeviceType('1.5')).toBeNull();
  });
});

describe('deviceTypeFromString', () => {
  it('falls back to Unknown Browser (14)', () => {
    expect(deviceTypeFromString('toaster')).toBe(DEVICE_TYPE.UnknownBrowser);
    expect(deviceTypeFromString('')).toBe(DEVICE_TYPE.UnknownBrowser);
  });

  it('keeps valid values', () => {
    expect(deviceTypeFromString('iOS')).toBe(DEVICE_TYPE.Ios);
  });
});

describe('deviceTypeDisplayName', () => {
  it('matches the Rust display names used in the devicetype claim', () => {
    expect(deviceTypeDisplayName(DEVICE_TYPE.Android)).toBe('Android');
    expect(deviceTypeDisplayName(DEVICE_TYPE.Ios)).toBe('iOS');
    expect(deviceTypeDisplayName(DEVICE_TYPE.ChromeExtension)).toBe('Chrome Extension');
    expect(deviceTypeDisplayName(DEVICE_TYPE.WindowsDesktop)).toBe('Windows');
    expect(deviceTypeDisplayName(DEVICE_TYPE.MacOsDesktop)).toBe('macOS');
    expect(deviceTypeDisplayName(DEVICE_TYPE.IEBrowser)).toBe('Internet Explorer');
    expect(deviceTypeDisplayName(DEVICE_TYPE.UnknownBrowser)).toBe('Unknown Browser');
    expect(deviceTypeDisplayName(DEVICE_TYPE.DuckDuckGoBrowser)).toBe('DuckDuckGo');
  });

  it('falls back for unknown numeric values', () => {
    expect(deviceTypeDisplayName(999)).toBe('Unknown Browser');
  });
});

describe('isPushDevice', () => {
  it('only Android and iOS can receive push', () => {
    expect(isPushDevice(DEVICE_TYPE.Android)).toBe(true);
    expect(isPushDevice(DEVICE_TYPE.Ios)).toBe(true);
    expect(isPushDevice(DEVICE_TYPE.ChromeBrowser)).toBe(false);
    expect(isPushDevice(DEVICE_TYPE.UnknownBrowser)).toBe(false);
  });
});
