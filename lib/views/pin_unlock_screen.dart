import 'dart:math';
import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter/services.dart';
import '../services/pin_unlock_service.dart';
import '../services/logger_service.dart';

/// PIN unlock screen with randomized keypad.
///
/// Security: digits 0-9 are shuffled (Fisher-Yates, CSPRNG) on each
/// display and after each failed attempt. This defeats:
///   - Shoulder surfing (positions don't map to fixed digits)
///   - Smudge attacks (touched positions ≠ digit sequence)
///   - Thermal imaging (heat map is meaningless)
///   - Camera recording (finger trajectory reveals nothing)
///
/// Layout: 3×4 grid (3 columns, 4 rows). Bottom row: digit[9], empty, ⌫.
/// Reshuffled once per unlock attempt + after each failure.
class PinUnlockScreen extends StatefulWidget {
  /// Called with the entered PIN. Returns true if correct.
  final Future<bool> Function(String pin) onPinSubmitted;

  /// Called when PIN fails too many times or user taps "Use password".
  final VoidCallback onFallbackToPassword;

  /// Whether this is PIN setup (enter twice) vs unlock (enter once).
  final bool isSetup;

  const PinUnlockScreen({
    super.key,
    required this.onPinSubmitted,
    required this.onFallbackToPassword,
    this.isSetup = false,
  });

  @override
  State<PinUnlockScreen> createState() => _PinUnlockScreenState();
}

class _PinUnlockScreenState extends State<PinUnlockScreen>
    with SingleTickerProviderStateMixin {
  static const _pinLength = 6;

  String _pin = '';
  String? _firstPin; // for setup mode: first entry
  bool _isLoading = false;
  String? _message;
  bool _isError = false;
  int _failedAttempts = 0;

  late List<int> _shuffledDigits;
  late AnimationController _shakeController;

  @override
  void initState() {
    super.initState();
    _reshuffleKeypad();
    _shakeController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 400),
    );
    if (widget.isSetup) {
      _message = 'Choose a 6-digit PIN';
      _isError = false;
    }
  }

  @override
  void dispose() {
    _shakeController.dispose();
    _pin = '';
    _firstPin = null;
    super.dispose();
  }

  void _reshuffleKeypad() {
    final rng = Random.secure();
    final digits = List<int>.generate(10, (i) => i);
    for (int i = digits.length - 1; i > 0; i--) {
      final j = rng.nextInt(i + 1);
      final tmp = digits[i];
      digits[i] = digits[j];
      digits[j] = tmp;
    }
    _shuffledDigits = digits;
  }

  void _onDigitPressed(int digit) {
    if (_isLoading || _pin.length >= _pinLength) return;
    HapticFeedback.lightImpact();
    setState(() {
      _pin += digit.toString();
      _message = null;
      _isError = false;
    });
    if (_pin.length == _pinLength) {
      _onPinComplete();
    }
  }

  void _onBackspace() {
    if (_isLoading || _pin.isEmpty) return;
    HapticFeedback.lightImpact();
    setState(() {
      _pin = _pin.substring(0, _pin.length - 1);
      // Reshuffle when backspaced to empty (prevents partial-entry inference)
      if (_pin.isEmpty) _reshuffleKeypad();
    });
  }

  void _onClearAll() {
    if (_isLoading || _pin.isEmpty) return;
    HapticFeedback.mediumImpact();
    setState(() {
      _pin = '';
      _reshuffleKeypad();
    });
  }

  Future<void> _onPinComplete() async {
    if (widget.isSetup) {
      await _handleSetup();
    } else {
      await _handleUnlock();
    }
  }

  Future<void> _handleSetup() async {
    if (_firstPin == null) {
      // First entry — ask to confirm
      _firstPin = _pin;
      setState(() {
        _pin = '';
        _message = 'Confirm your PIN';
        _isError = false;
      });
      _reshuffleKeypad();
      return;
    }

    // Second entry — compare
    if (_pin == _firstPin) {
      setState(() => _isLoading = true);
      final success = await widget.onPinSubmitted(_pin);
      if (!mounted) return;
      if (!success) {
        setState(() {
          _isLoading = false;
          _pin = '';
          _firstPin = null;
          _message = 'Failed to set PIN. Try again.';
          _isError = true;
        });
        _reshuffleKeypad();
      }
      // If success, parent handles navigation
    } else {
      await _shakeController.forward(from: 0);
      setState(() {
        _pin = '';
        _firstPin = null;
        _message = 'PINs don\'t match. Start over.';
        _isError = true;
      });
      _reshuffleKeypad();
    }
  }

  Future<void> _handleUnlock() async {
    setState(() => _isLoading = true);

    // Check for lockout delay before attempting
    final delay = await PinUnlockService.getLockoutDelay();
    if (delay > 0) {
      for (var s = delay; s > 0; s--) {
        if (!mounted) return;
        setState(() {
          _message = 'Wait ${s}s before retry';
          _isError = true;
        });
        await Future.delayed(const Duration(seconds: 1));
      }
    }

    final success = await widget.onPinSubmitted(_pin);
    if (!mounted) return;

    if (success) return;

    _failedAttempts++;
    await _shakeController.forward(from: 0);

    if (_failedAttempts >= PinUnlockService.maxFailedAttempts) {
      widget.onFallbackToPassword();
      return;
    }

    setState(() {
      _isLoading = false;
      _pin = '';
      _message =
          'Incorrect PIN ($_failedAttempts/${PinUnlockService.maxFailedAttempts})';
      _isError = true;
    });
    _reshuffleKeypad();
  }

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);

    return ScaffoldPage(
      content: Center(
        child: SizedBox(
          width: 320,
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Spacer(flex: 2),
              // Lock icon
              Icon(FluentIcons.lock, size: 48, color: theme.accentColor),
              const SizedBox(height: 16),
              Text(
                widget.isSetup ? 'Set PIN' : 'Enter PIN',
                style: theme.typography.subtitle,
              ),
              const SizedBox(height: 24),
              // PIN dots with shake animation
              Semantics(
                label: '${_pin.length} of $_pinLength digits entered',
                child: _buildPinDots(theme),
              ),
              const SizedBox(height: 12),
              // Message
              if (_message != null)
                Text(
                  _message!,
                  style: theme.typography.caption?.copyWith(
                    color: _isError ? Colors.red : theme.inactiveColor,
                  ),
                ),
              const SizedBox(height: 32),
              // Randomized keypad
              _isLoading
                  ? const SizedBox(
                      height: 340,
                      child: Center(child: ProgressRing()),
                    )
                  : _buildKeypad(theme),
              const Spacer(),
              // Fallback link
              if (!widget.isSetup)
                HyperlinkButton(
                  onPressed: widget.onFallbackToPassword,
                  child: const Text('Use master password instead'),
                ),
              const SizedBox(height: 24),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildPinDots(FluentThemeData theme) {
    return AnimatedBuilder(
      animation: _shakeController,
      builder: (context, child) {
        final progress = _shakeController.value;
        final dx = _shakeController.isAnimating
            ? 10 * sin(progress * 3.14159 * 4) * (1 - progress)
            : 0.0;
        return Transform.translate(offset: Offset(dx, 0), child: child);
      },
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: List.generate(_pinLength, (i) {
          final filled = i < _pin.length;
          return AnimatedContainer(
            duration: const Duration(milliseconds: 120),
            margin: const EdgeInsets.symmetric(horizontal: 8),
            width: 16,
            height: 16,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: filled ? theme.accentColor : Colors.transparent,
              border: Border.all(color: theme.accentColor, width: 2),
            ),
          );
        }),
      ),
    );
  }

  Widget _buildKeypad(FluentThemeData theme) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        for (int row = 0; row < 3; row++)
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              for (int col = 0; col < 3; col++)
                _digitKey(_shuffledDigits[row * 3 + col], theme),
            ],
          ),
        // Bottom row: digit[9], empty, backspace
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            _digitKey(_shuffledDigits[9], theme),
            const SizedBox(width: 80, height: 80), // empty cell
            _backspaceKey(theme),
          ],
        ),
      ],
    );
  }

  Widget _digitKey(int digit, FluentThemeData theme) {
    return Semantics(
      label: digit.toString(),
      button: true,
      child: GestureDetector(
        onTap: () => _onDigitPressed(digit),
        child: Container(
          width: 72,
          height: 72,
          margin: const EdgeInsets.all(4),
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: theme.cardColor,
            border: Border.all(
              color: theme.resources.controlStrokeColorDefault,
            ),
          ),
          alignment: Alignment.center,
          child: Text(
            digit.toString(),
            style: theme.typography.title?.copyWith(
              fontWeight: FontWeight.w400,
            ),
          ),
        ),
      ),
    );
  }

  Widget _backspaceKey(FluentThemeData theme) {
    return Semantics(
      label: 'Delete',
      button: true,
      child: GestureDetector(
        onTap: _onBackspace,
        onLongPress: _onClearAll, // long-press clears all digits
        child: Container(
          width: 72,
          height: 72,
          margin: const EdgeInsets.all(4),
          alignment: Alignment.center,
          child: Icon(FluentIcons.backspace, size: 24,
              color: theme.typography.body?.color),
        ),
      ),
    );
  }
}
