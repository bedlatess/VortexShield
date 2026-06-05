# VortexShield Phase 1 Design

## Scope

Phase 1 implements the backend challenge generation service described in the provided specification:

- `GET /api/captcha/challenge`
- Dynamic captcha image synthesis with no static image library
- Random Bezier interference lines
- Four randomly selected symbols with randomized scale, rotation, and color
- Collision-free element placement using bounding-box intersection checks
- Global sine-based fluid ripple deformation using NumPy and Pillow
- In-memory mock session storage for token-to-answer metadata

## Architecture

The FastAPI app is split into small modules:

- `app/main.py`: application factory and router mounting
- `app/api/routes/captcha.py`: public captcha API route
- `app/services/captcha_generator.py`: image synthesis and metadata generation
- `app/services/session_store.py`: thread-safe mock cache interface
- `app/schemas/captcha.py`: response models aligned with chapter 5 API payloads
- `app/core/config.py`: runtime settings

The session store intentionally exposes `put/get/delete` methods so it can be replaced by Redis without changing route logic in later phases.

## Data Flow

1. Client calls `GET /api/captcha/challenge`.
2. Backend generates a unique `captcha_token`.
3. `generate_captcha_challenge` returns a Base64 image, a prompt, and private answer metadata.
4. The route stores private metadata in `SessionStore`.
5. The response returns only public challenge data: token, image, prompt, and dimensions.

## Security Notes

The generator records bounding boxes after symbol placement but before final ripple deformation. The ripple amplitude is intentionally bounded so the stored hit regions still cover the visible target area. Later phases can add a tolerance-expanded verification box or store warped masks if stricter geometry is required.

Phase 1 does not expose answer metadata to clients.

