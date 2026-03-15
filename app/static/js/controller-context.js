/* Shared controller selection context for all frontend pages. */
(function () {
    const STORAGE_KEY = "unifi-toolkit-selected-controller";
    const CHANGE_EVENT = "controller-context-changed";

    function parseMaybeUrl(value) {
        try {
            return new URL(value, window.location.origin);
        } catch {
            return null;
        }
    }

    const state = {
        loaded: false,
        controllers: [],
        selectedKey: null,
    };

    function activeControllers() {
        return state.controllers.filter((controller) => controller.is_active);
    }

    function defaultController() {
        return activeControllers().find((controller) => controller.is_default) || null;
    }

    function hasController(controllerKey) {
        return activeControllers().some((controller) => controller.controller_key === controllerKey);
    }

    function selectedController() {
        if (!state.selectedKey) {
            return null;
        }
        return state.controllers.find((controller) => controller.controller_key === state.selectedKey) || null;
    }

    function dispatchChanged() {
        window.dispatchEvent(
            new CustomEvent(CHANGE_EVENT, {
                detail: {
                    selectedKey: state.selectedKey,
                    selectedController: selectedController(),
                    controllers: state.controllers.slice(),
                    activeControllers: activeControllers(),
                },
            })
        );
    }

    function saveSelection(key) {
        if (key) {
            localStorage.setItem(STORAGE_KEY, key);
        } else {
            localStorage.removeItem(STORAGE_KEY);
        }
    }

    function resolveInitialSelection() {
        const urlKey = new URLSearchParams(window.location.search).get("controller_key");
        if (urlKey && hasController(urlKey)) {
            return urlKey;
        }
        const storedKey = localStorage.getItem(STORAGE_KEY);
        if (storedKey && hasController(storedKey)) {
            return storedKey;
        }
        const defaultEntry = defaultController();
        if (defaultEntry) {
            return defaultEntry.controller_key;
        }
        const firstActive = activeControllers()[0];
        return firstActive ? firstActive.controller_key : null;
    }

    function addControllerKeyToUrl(url, explicitControllerKey) {
        const controllerKey = explicitControllerKey || state.selectedKey;
        if (!controllerKey) {
            return url;
        }

        const parsed = parseMaybeUrl(url);
        if (!parsed) {
            return url;
        }

        if (!parsed.searchParams.get("controller_key")) {
            parsed.searchParams.set("controller_key", controllerKey);
        }

        if (parsed.origin === window.location.origin) {
            return parsed.pathname + parsed.search + parsed.hash;
        }
        return parsed.toString();
    }

    function syncBrowserUrlParam() {
        if (!state.selectedKey) {
            return;
        }
        const current = new URL(window.location.href);
        const currentKey = current.searchParams.get("controller_key");
        if (currentKey === state.selectedKey) {
            return;
        }
        current.searchParams.set("controller_key", state.selectedKey);
        window.history.replaceState({}, "", current.pathname + current.search + current.hash);
    }

    async function loadControllers() {
        const response = await fetch("/api/config/controllers", {
            headers: {
                "X-Requested-With": "XMLHttpRequest",
            },
        });
        if (!response.ok) {
            throw new Error("Failed to load controllers");
        }
        state.controllers = await response.json();
        state.selectedKey = resolveInitialSelection();
        saveSelection(state.selectedKey);
        state.loaded = true;
        dispatchChanged();
        return {
            controllers: state.controllers.slice(),
            selectedKey: state.selectedKey,
        };
    }

    function setSelectedController(controllerKey, options = {}) {
        const { persist = true, updateUrl = true, dispatch = true } = options;
        if (controllerKey && !hasController(controllerKey)) {
            return false;
        }
        state.selectedKey = controllerKey || null;
        if (persist) {
            saveSelection(state.selectedKey);
        }
        if (updateUrl) {
            syncBrowserUrlParam();
        }
        if (dispatch) {
            dispatchChanged();
        }
        return true;
    }

    function apiFetch(url, options) {
        return fetch(addControllerKeyToUrl(url), options);
    }

    function websocketUrl(path, explicitControllerKey) {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const base = `${protocol}//${window.location.host}${path}`;
        return addControllerKeyToUrl(base, explicitControllerKey);
    }

    function decorateLinks() {
        document.querySelectorAll("[data-controller-link]").forEach((anchor) => {
            const original = anchor.getAttribute("data-controller-href") || anchor.getAttribute("href");
            if (!original) {
                return;
            }
            anchor.setAttribute("data-controller-href", original);
            anchor.setAttribute("href", addControllerKeyToUrl(original));
        });
    }

    function initSelectorUi(options = {}) {
        const {
            wrapId = "controller-selector-wrap",
            selectId = "controller-selector",
            badgeId = "controller-current-badge",
            singlePrefix = "Controller: ",
            noControllersLabel = "No controller configured",
            onChange = () => window.location.reload(),
        } = options;

        const wrap = document.getElementById(wrapId);
        const select = document.getElementById(selectId);
        const badge = document.getElementById(badgeId);
        if (!wrap || !select || !badge) {
            return;
        }

        const active = activeControllers();
        const selected = selectedController();
        wrap.style.display = "flex";

        if (active.length > 1) {
            select.style.display = "inline-block";
            badge.style.display = "none";
            select.innerHTML = active
                .map(
                    (c) =>
                        `<option value="${c.controller_key}">${c.display_name}${c.is_default ? " (default)" : ""}</option>`
                )
                .join("");
            select.value = selected?.controller_key || active[0].controller_key;
            select.onchange = () => {
                setSelectedController(select.value);
                onChange(select.value);
            };
            return;
        }

        select.style.display = "none";
        badge.style.display = "inline-flex";
        if (active.length === 1) {
            badge.textContent = `${singlePrefix}${active[0].display_name}`;
            return;
        }
        badge.textContent = noControllersLabel;
    }

    window.addEventListener(CHANGE_EVENT, decorateLinks);

    window.ControllerContext = {
        changeEvent: CHANGE_EVENT,
        loadControllers,
        getControllers: () => state.controllers.slice(),
        getActiveControllers: () => activeControllers(),
        getSelectedControllerKey: () => state.selectedKey,
        getSelectedController: () => selectedController(),
        hasControllers: () => state.controllers.length > 0,
        shouldShowSelector: () => activeControllers().length > 1,
        addControllerKeyToUrl,
        apiFetch,
        websocketUrl,
        setSelectedController,
        syncBrowserUrlParam,
        decorateLinks,
        initSelectorUi,
    };
})();
