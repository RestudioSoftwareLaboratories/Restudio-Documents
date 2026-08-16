// ========== SECURITY UTILITIES ==========

function sanitizeText(text) {
    if (text === null || text === undefined) return '';
    if (typeof text !== 'string') return String(text);
    var map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;',
        '=': '&#x3D;',
        '`': '&#x60;'
    };
    return text.replace(/[&<>"'/=`]/g, function(match) { return map[match]; });
}

function isValidText(text) {
    if (typeof text !== 'string') return false;
    var dangerousPatterns = [
        /javascript:/i, /on\w+\s*=/i, /<script/i, /<iframe/i,
        /<object/i, /<embed/i, /data:text\/html/i, /vbscript:/i
    ];
    for (var i = 0; i < dangerousPatterns.length; i++) {
        if (dangerousPatterns[i].test(text)) return false;
    }
    return true;
}

function validateREDCFile(data) {
    if (!data || typeof data !== 'object') throw new Error('Invalid file format');
    var MAX_FILE_SIZE_MB = 20;
    var jsonString = JSON.stringify(data);
    var sizeInMB = new Blob([jsonString]).size / (1024 * 1024);
    if (sizeInMB > MAX_FILE_SIZE_MB) throw new Error('File too large: ' + sizeInMB.toFixed(2) + 'MB (max ' + MAX_FILE_SIZE_MB + 'MB)');
    if (data.objects && !Array.isArray(data.objects)) throw new Error('Invalid file: Objects must be an array');
    if (data.objects) {
        for (var i = 0; i < data.objects.length; i++) {
            var obj = data.objects[i];
            if (!obj || typeof obj !== 'object') throw new Error('Invalid object at index ' + i);
            var allowedTypes = ['textbox', 'rect', 'circle', 'image', 'group'];
            if (obj.type && allowedTypes.indexOf(obj.type) === -1) throw new Error('Invalid object type: ' + obj.type);
            if (obj.type === 'textbox' && obj.text) {
                if (!isValidText(obj.text)) throw new Error('Suspicious content detected in text object');
                obj.text = sanitizeText(obj.text);
            }
        }
    }
    return true;
}

function validateCanvasAccess(canvasInstance) {
    if (!canvasInstance) { console.warn('Canvas not initialized'); return false; }
    if (typeof canvasInstance.getActiveObject !== 'function') { console.warn('Canvas is not properly initialized'); return false; }
    return true;
}

function getActiveObjectSafe(canvasInstance) {
    if (!validateCanvasAccess(canvasInstance)) return null;
    try { return canvasInstance.getActiveObject(); } catch (err) { console.error('Error getting active object:', err); return null; }
}

function getActiveObjectsSafe(canvasInstance) {
    if (!validateCanvasAccess(canvasInstance)) return [];
    try { return canvasInstance.getActiveObjects() || []; } catch (err) { console.error('Error getting active objects:', err); return []; }
}

// ========== MAIN APPLICATION ==========

(function() {
    'use strict';
    
    var container = document.getElementById('fabric-canvas-container');
    var zoomLevelDisplay = document.getElementById('zoomLevelDisplay');
    var undoBtn = document.querySelector('[data-action="undo"]');
    var redoBtn = document.querySelector('[data-action="redo"]');
    var boldBtn = document.querySelector('[data-action="bold"]');
    var italicBtn = document.querySelector('[data-action="italic"]');
    var underlineBtn = document.querySelector('[data-action="underline"]');
    var alignLeftBtn = document.querySelector('[data-action="alignLeft"]');
    var alignCenterBtn = document.querySelector('[data-action="alignCenter"]');
    var alignRightBtn = document.querySelector('[data-action="alignRight"]');
    var fillColorBtn = document.getElementById('fillColorBtn');
    var bgColorBtn = document.getElementById('bgColorBtn');

    var canvas = null;
    var historyStack = [];
    var historyIndex = -1;
    var zoomLevel = 1;
    var historySaveTimer = null;
    var hasUnsavedChanges = false;
    var isInitialized = false;

    function initCanvas() {
        if (!container) { console.error('Container not found'); return; }
        var existingCanvas = document.getElementById('fabric-canvas');
        if (existingCanvas) existingCanvas.remove();
        var newCanvasElem = document.createElement('canvas');
        newCanvasElem.id = 'fabric-canvas';
        newCanvasElem.width = container.clientWidth || 900;
        newCanvasElem.height = container.clientHeight || 600;
        container.innerHTML = '';
        container.appendChild(newCanvasElem);

        try {
            canvas = new fabric.Canvas('fabric-canvas', {
                preserveObjectStacking: true,
                selection: true,
                renderOnAddRemove: true,
                selectionColor: 'rgba(0, 100, 200, 0.2)',
                selectionDashArray: [5, 5],
                evented: true,
                perPixelTargetFind: true,
                targetFindTolerance: 3,
                interactive: true
            });
            canvas.setWidth(container.clientWidth);
            canvas.setHeight(container.clientHeight);
            canvas.renderAll();
            setupCanvasEvents();
            isInitialized = true;
            resetHistoryFromCurrentCanvas();
            updateZoomDisplay();
            updateUndoRedoButtons();
            if (fillColorBtn) fillColorBtn.disabled = true;
            if (bgColorBtn) bgColorBtn.disabled = true;
            console.log('Canvas initialized successfully');
        } catch (err) {
            console.error('Error initializing canvas:', err);
            isInitialized = false;
        }
    }

    function setupCanvasEvents() {
        if (!canvas) return;
        canvas.off('object:added'); canvas.off('object:modified'); canvas.off('object:removed');
        canvas.off('selection:created'); canvas.off('selection:updated'); canvas.off('selection:cleared');
        canvas.on('object:added', function() { scheduleHistorySave(); });
        canvas.on('object:modified', function() { scheduleHistorySave(); });
        canvas.on('object:removed', function() { scheduleHistorySave(); });
        canvas.on('selection:created', function() { updateStyleButtonsState(); });
        canvas.on('selection:updated', function() { updateStyleButtonsState(); });
        canvas.on('selection:cleared', function() {
            if (boldBtn) boldBtn.classList.remove('active');
            if (italicBtn) italicBtn.classList.remove('active');
            if (underlineBtn) underlineBtn.classList.remove('active');
            if (alignLeftBtn) alignLeftBtn.classList.remove('active');
            if (alignCenterBtn) alignCenterBtn.classList.remove('active');
            if (alignRightBtn) alignRightBtn.classList.remove('active');
            updateFontSizeCheckmark(null);
            updateLineHeightCheckmark(null);
            if (fillColorBtn) fillColorBtn.disabled = true;
            if (bgColorBtn) bgColorBtn.disabled = true;
        });
    }

    function saveHistoryState() {
        if (!canvas || !isInitialized) return;
        try {
            var state = JSON.stringify(canvas.toJSON(['id', 'customType']));
            if (historyStack.length === 0 || historyStack[historyIndex] !== state) {
                historyStack = historyStack.slice(0, historyIndex + 1);
                historyStack.push(state);
                historyIndex++;
                markAsChanged();
            }
            updateUndoRedoButtons();
        } catch (err) { console.error('Error saving history:', err); }
    }

    function scheduleHistorySave() {
        if (historySaveTimer) clearTimeout(historySaveTimer);
        historySaveTimer = setTimeout(saveHistoryState, 150);
    }

    function resetHistoryFromCurrentCanvas() {
        if (!canvas || !isInitialized) return;
        try {
            historyStack = [];
            historyIndex = -1;
            var state = JSON.stringify(canvas.toJSON(['id', 'customType']));
            historyStack.push(state);
            historyIndex = 0;
            updateUndoRedoButtons();
        } catch (err) { console.error('Error resetting history:', err); }
    }

    function loadHistoryState() {
        if (!canvas || !isInitialized || historyStack.length === 0) return;
        try {
            canvas.loadFromJSON(historyStack[historyIndex], function() {
                canvas.renderAll();
                updateUndoRedoButtons();
                updateStyleButtonsState();
            });
        } catch (err) { console.error('Error loading history state:', err); }
    }

    function undo() {
        if (historyIndex > 0 && canvas && isInitialized) { historyIndex--; loadHistoryState(); }
    }

    function redo() {
        if (historyIndex < historyStack.length - 1 && canvas && isInitialized) { historyIndex++; loadHistoryState(); }
    }

    function updateUndoRedoButtons() {
        if (undoBtn) undoBtn.disabled = (historyIndex <= 0);
        if (redoBtn) redoBtn.disabled = (historyIndex >= historyStack.length - 1);
    }

    function markAsChanged() { hasUnsavedChanges = true; }

    function isImage(obj) { return obj && obj.type === 'image'; }

    function updateStyleButtonsState() {
        if (!canvas || !isInitialized) return;
        var activeObj = getActiveObjectSafe(canvas);
        if (!activeObj) {
            if (boldBtn) boldBtn.classList.remove('active');
            if (italicBtn) italicBtn.classList.remove('active');
            if (underlineBtn) underlineBtn.classList.remove('active');
            if (alignLeftBtn) alignLeftBtn.classList.remove('active');
            if (alignCenterBtn) alignCenterBtn.classList.remove('active');
            if (alignRightBtn) alignRightBtn.classList.remove('active');
            updateFontSizeCheckmark(null);
            updateLineHeightCheckmark(null);
            if (fillColorBtn) fillColorBtn.disabled = true;
            if (bgColorBtn) bgColorBtn.disabled = true;
            return;
        }
        var img = isImage(activeObj);
        if (activeObj.type === 'textbox') {
            if (boldBtn) boldBtn.classList.toggle('active', activeObj.fontWeight === 'bold');
            if (italicBtn) italicBtn.classList.toggle('active', activeObj.fontStyle === 'italic');
            if (underlineBtn) underlineBtn.classList.toggle('active', !!activeObj.underline);
            var align = activeObj.textAlign || 'left';
            if (alignLeftBtn) alignLeftBtn.classList.toggle('active', align === 'left');
            if (alignCenterBtn) alignCenterBtn.classList.toggle('active', align === 'center');
            if (alignRightBtn) alignRightBtn.classList.toggle('active', align === 'right');
            updateFontSizeCheckmark(activeObj.fontSize);
            updateLineHeightCheckmark(activeObj.lineHeight);
            if (fillColorBtn) fillColorBtn.disabled = false;
            if (bgColorBtn) bgColorBtn.disabled = false;
        } else {
            if (boldBtn) boldBtn.classList.remove('active');
            if (italicBtn) italicBtn.classList.remove('active');
            if (underlineBtn) underlineBtn.classList.remove('active');
            if (alignLeftBtn) alignLeftBtn.classList.remove('active');
            if (alignCenterBtn) alignCenterBtn.classList.remove('active');
            if (alignRightBtn) alignRightBtn.classList.remove('active');
            updateFontSizeCheckmark(null);
            updateLineHeightCheckmark(null);
            if (fillColorBtn) fillColorBtn.disabled = img;
            if (bgColorBtn) bgColorBtn.disabled = true;
        }
    }

    function updateFontSizeCheckmark(fontSize) {
        var items = document.querySelectorAll('#fontSizeMenu .dropdown-item');
        for (var i = 0; i < items.length; i++) {
            var check = items[i].querySelector('.check-icon');
            if (check) {
                var size = parseInt(items[i].dataset.fontsize);
                check.style.display = (fontSize && size === fontSize) ? 'inline' : 'none';
            }
        }
    }

    function updateLineHeightCheckmark(lineHeight) {
        var items = document.querySelectorAll('#lineHeightMenu .dropdown-item');
        for (var i = 0; i < items.length; i++) {
            var check = items[i].querySelector('.check-icon');
            if (check) {
                var val = parseFloat(items[i].dataset.lineheight);
                check.style.display = (lineHeight && Math.abs(val - lineHeight) < 0.01) ? 'inline' : 'none';
            }
        }
    }

    var presetColors = [
        '#ffffff', '#000000', '#e74c3c', '#e67e22', '#f1c40f', '#2ecc71',
        '#1abc9c', '#3498db', '#9b59b6', '#ecf0f1', '#c0392b', '#2980b9',
        '#8e44ad', '#2c3e50', '#16a085', '#27ae60', '#f39c12', '#d35400',
        '#7f8c8d', '#bdc3c7', '#34495e', '#95a5a6'
    ];

    function buildColorPalette(gridId, customInputId, callback) {
        var grid = document.getElementById(gridId);
        if (!grid) return;
        grid.innerHTML = '';
        for (var i = 0; i < presetColors.length; i++) {
            var color = presetColors[i];
            var swatch = document.createElement('div');
            swatch.className = 'color-swatch';
            swatch.style.backgroundColor = color;
            swatch.addEventListener('click', function(c) {
                return function(e) {
                    e.stopPropagation();
                    callback(c);
                    var customInput = document.getElementById(customInputId);
                    if (customInput) customInput.value = c;
                    var popup = grid.closest('.color-picker-popup');
                    if (popup) popup.classList.remove('show');
                };
            }(color));
            grid.appendChild(swatch);
        }
        var customInput = document.getElementById(customInputId);
        if (customInput) {
            customInput.addEventListener('input', function(e) { callback(e.target.value); });
        }
    }

    function addTextBox() {
        if (!canvas || !isInitialized) return;
        var textbox = new fabric.Textbox('New Text', {
            left: 100, top: 100, width: 200, fontSize: 24, fill: '#ffffff',
            fontFamily: 'Segoe UI', hasControls: true, hasBorders: true,
            selectable: true, evented: true, hoverCursor: 'pointer', moveCursor: 'move', perPixelTargetFind: true
        });
        canvas.add(textbox);
        canvas.setActiveObject(textbox);
        canvas.renderAll();
        scheduleHistorySave();
    }

    function addRectangle() {
        if (!canvas || !isInitialized) return;
        var rect = new fabric.Rect({
            left: 150, top: 150, width: 120, height: 80, fill: '#3498db',
            stroke: '#ffffff', strokeWidth: 2, selectable: true, evented: true,
            hoverCursor: 'pointer', moveCursor: 'move', perPixelTargetFind: true
        });
        canvas.add(rect);
        canvas.setActiveObject(rect);
        canvas.renderAll();
        scheduleHistorySave();
    }

    function addCircle() {
        if (!canvas || !isInitialized) return;
        var circle = new fabric.Circle({
            left: 200, top: 200, radius: 50, fill: '#e67e22', stroke: '#fff',
            strokeWidth: 2, selectable: true, evented: true,
            hoverCursor: 'pointer', moveCursor: 'move', perPixelTargetFind: true
        });
        canvas.add(circle);
        canvas.setActiveObject(circle);
        canvas.renderAll();
        scheduleHistorySave();
    }

    function addImageFromFile() { var input = document.getElementById('imageFileInput'); if (input) input.click(); }

    function addQRCode() {
        if (!canvas || !isInitialized) return;
        var text = prompt('Enter text or URL for the QR code:', 'https://restudio.com');
        if (!text || !text.trim()) return;
        var sanitizedText = sanitizeText(text.trim());
        if (!isValidText(sanitizedText)) { alert('Invalid text detected.'); return; }
        var qrUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(sanitizedText);
        fabric.Image.fromURL(qrUrl, function(img) {
            if (!canvas || !isInitialized) return;
            img.set({
                left: (canvas.width - img.width * img.scaleX) / 2,
                top: (canvas.height - img.height * img.scaleY) / 2,
                selectable: true, evented: true, hoverCursor: 'pointer', moveCursor: 'move', perPixelTargetFind: true
            });
            canvas.add(img);
            canvas.setActiveObject(img);
            canvas.renderAll();
            scheduleHistorySave();
        }, { crossOrigin: 'anonymous' });
    }

    function handleImageFileSelect(event) {
        var file = event.target.files[0];
        if (!file) return;
        if (!file.type.startsWith('image/')) { alert('Please select a valid image file.'); event.target.value = ''; return; }
        var MAX_IMAGE_SIZE = 10 * 1024 * 1024;
        if (file.size > MAX_IMAGE_SIZE) { alert('Image file too large: ' + (file.size / 1024 / 1024).toFixed(2) + 'MB (max 10MB)'); event.target.value = ''; return; }
        var reader = new FileReader();
        reader.onload = function(e) {
            if (!canvas || !isInitialized) return;
            fabric.Image.fromURL(e.target.result, function(img) {
                if (!canvas || !isInitialized) return;
                var maxWidth = canvas.width * 0.6;
                var maxHeight = canvas.height * 0.6;
                if (img.width > maxWidth || img.height > maxHeight) {
                    var scale = Math.min(maxWidth / img.width, maxHeight / img.height);
                    img.scale(scale);
                } else { img.scale(1); }
                img.set({
                    left: (canvas.width - img.width * img.scaleX) / 2,
                    top: (canvas.height - img.height * img.scaleY) / 2,
                    selectable: true, evented: true, hoverCursor: 'pointer', moveCursor: 'move', perPixelTargetFind: true
                });
                canvas.add(img);
                canvas.setActiveObject(img);
                canvas.renderAll();
                scheduleHistorySave();
            }, { crossOrigin: 'anonymous' });
        };
        reader.onerror = function() { alert('Failed to load image file.'); };
        reader.readAsDataURL(file);
        event.target.value = '';
    }

    function deleteSelected() {
        if (!canvas || !isInitialized) return;
        var active = canvas.getActiveObjects();
        if (active.length > 0) {
            for (var i = 0; i < active.length; i++) { canvas.remove(active[i]); }
            canvas.discardActiveObject();
            canvas.renderAll();
            scheduleHistorySave();
        }
    }

    function bringForward() {
        if (!canvas || !isInitialized) return;
        var obj = getActiveObjectSafe(canvas);
        if (obj) { canvas.bringForward(obj); canvas.renderAll(); scheduleHistorySave(); }
    }

    function sendBackward() {
        if (!canvas || !isInitialized) return;
        var obj = getActiveObjectSafe(canvas);
        if (obj) { canvas.sendBackwards(obj); canvas.renderAll(); scheduleHistorySave(); }
    }

    function applyToSelected(callback) {
        if (!canvas || !isInitialized) return;
        var actives = canvas.getActiveObjects();
        if (actives.length > 0) {
            for (var i = 0; i < actives.length; i++) { callback(actives[i]); }
            canvas.renderAll();
            scheduleHistorySave();
            updateStyleButtonsState();
        }
    }

    function setBold() { applyToSelected(function(obj) { if (obj.type === 'textbox') { obj.fontWeight = (obj.fontWeight === 'bold') ? 'normal' : 'bold'; } }); }
    function setItalic() { applyToSelected(function(obj) { if (obj.type === 'textbox') { obj.fontStyle = (obj.fontStyle === 'italic') ? 'normal' : 'italic'; } }); }
    function setUnderline() { applyToSelected(function(obj) { if (obj.type === 'textbox') { obj.underline = !obj.underline; } }); }
    function setFontSize(size) { applyToSelected(function(obj) { if (obj.fontSize !== undefined) { obj.fontSize = parseInt(size); } }); var container = document.getElementById('fontSizeContainer'); if (container) container.classList.remove('open'); }
    function setLineHeight(height) { applyToSelected(function(obj) { if (obj.lineHeight !== undefined) { obj.lineHeight = parseFloat(height); } }); var container = document.getElementById('lineHeightContainer'); if (container) container.classList.remove('open'); }
    function setFillColor(color) { applyToSelected(function(obj) { if (obj.type !== 'image') { obj.set('fill', color); } }); }
    function setBackgroundColor(color) { applyToSelected(function(obj) { if (obj.type === 'textbox') { obj.set('backgroundColor', color); } }); }
    function setTextAlign(align) { applyToSelected(function(obj) { if (obj.textAlign !== undefined) { obj.textAlign = align; } }); }
    function setCanvasBgColor(color) { if (!canvas || !isInitialized) return; canvas.setBackgroundColor(color, function() { canvas.renderAll(); }); markAsChanged(); }
    function increaseIndent() { applyToSelected(function(obj) { if (obj.type === 'textbox') { obj.text = '    ' + obj.text; } }); }
    function decreaseIndent() { applyToSelected(function(obj) { if (obj.type === 'textbox') { obj.text = obj.text.replace(/^ {1,4}/, ''); } }); }
    function transformText(type) {
        applyToSelected(function(obj) {
            if (obj.type === 'textbox') {
                if (type === 'uppercase') obj.text = obj.text.toUpperCase();
                else if (type === 'lowercase') obj.text = obj.text.toLowerCase();
                else if (type === 'capitalize') obj.text = obj.text.replace(/\b\w/g, function(c) { return c.toUpperCase(); });
            }
        });
        var container = document.getElementById('textTransformContainer');
        if (container) container.classList.remove('open');
    }

    function updateZoomDisplay() { if (zoomLevelDisplay) { zoomLevelDisplay.textContent = Math.round(zoomLevel * 100) + '%'; } }
    function zoomIn() { if (!canvas || !isInitialized) return; zoomLevel = Math.min(2, zoomLevel + 0.1); canvas.setZoom(zoomLevel); canvas.renderAll(); updateZoomDisplay(); }
    function zoomOut() { if (!canvas || !isInitialized) return; zoomLevel = Math.max(0.5, zoomLevel - 0.1); canvas.setZoom(zoomLevel); canvas.renderAll(); updateZoomDisplay(); }

    function exportAsREDC() {
        if (!canvas || !isInitialized) return;
        try {
            var dataStr = JSON.stringify(canvas.toJSON(['id']), null, 2);
            var blob = new Blob([dataStr], { type: 'application/json' });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'canvas.redc';
            a.click();
            URL.revokeObjectURL(url);
            hasUnsavedChanges = false;
        } catch (err) { alert('Error exporting file: ' + err.message); }
    }

    function importJSON(file) {
        if (!canvas || !isInitialized) return;
        if (hasUnsavedChanges && !confirm('Importing will replace the current canvas content. Are you sure?')) return;
        var reader = new FileReader();
        reader.onload = function(e) {
            try {
                var json = JSON.parse(e.target.result);
                validateREDCFile(json);
                canvas.loadFromJSON(json, function() {
                    canvas.renderAll();
                    resetHistoryFromCurrentCanvas();
                    updateZoomDisplay();
                    hasUnsavedChanges = false;
                });
            } catch (err) { alert('Import failed: ' + err.message); }
        };
        reader.onerror = function() { alert('Error reading file.'); };
        reader.readAsText(file);
    }

    // ========== KEYBOARD SHORTCUTS (المصلحة) ==========
    function setupKeyboardShortcuts() {
        document.addEventListener('keydown', function(e) {
            // تجاهل إذا كان التركيز على حقل إدخال نصي
            var tag = document.activeElement ? document.activeElement.tagName.toLowerCase() : '';
            if (tag === 'input' || tag === 'textarea' || tag === 'select') {
                return;
            }

            // Ctrl+Z - Undo
            if (e.ctrlKey && e.key === 'z') {
                e.preventDefault();
                undo();
                return;
            }
            // Ctrl+Y - Redo
            if (e.ctrlKey && e.key === 'y') {
                e.preventDefault();
                redo();
                return;
            }
            // Delete - Delete selected
            if (e.key === 'Delete' && !e.ctrlKey && !e.altKey) {
                e.preventDefault();
                deleteSelected();
                return;
            }
            // Escape - Exit focus mode
            if (e.key === 'Escape' && document.body.classList.contains('focus-mode')) {
                document.body.classList.remove('focus-mode');
                return;
            }
        });
    }

    // ========== Event Listeners ==========
    function setupEventListeners() {
        var toolbar = document.getElementById('toolbar');
        if (toolbar) {
            toolbar.addEventListener('click', function(e) {
                var btn = e.target.closest('.tool-btn');
                if (!btn || btn.closest('.dropdown-container')) return;
                var action = btn.dataset.action;
                if (action) {
                    switch(action) {
                        case 'undo': undo(); break;
                        case 'redo': redo(); break;
                        case 'deleteSelected': deleteSelected(); break;
                        case 'addText': addTextBox(); break;
                        case 'addImage': addImageFromFile(); break;
                        case 'addRectangle': addRectangle(); break;
                        case 'addCircle': addCircle(); break;
                        case 'addQR': addQRCode(); break;
                        case 'bold': setBold(); break;
                        case 'italic': setItalic(); break;
                        case 'underline': setUnderline(); break;
                        case 'alignLeft': setTextAlign('left'); break;
                        case 'alignCenter': setTextAlign('center'); break;
                        case 'alignRight': setTextAlign('right'); break;
                        case 'bringForward': bringForward(); break;
                        case 'sendBackward': sendBackward(); break;
                        case 'zoomIn': zoomIn(); break;
                        case 'zoomOut': zoomOut(); break;
                        case 'focusMode': document.body.classList.toggle('focus-mode'); break;
                        case 'exportRedc': exportAsREDC(); break;
                        case 'indentInc': increaseIndent(); break;
                        case 'indentDec': decreaseIndent(); break;
                    }
                }
            });
        }

        var imageInput = document.getElementById('imageFileInput');
        if (imageInput) { imageInput.addEventListener('change', handleImageFileSelect); }

        var importBtn = document.getElementById('importJsonBtn');
        var importInput = document.getElementById('importFileInput');
        if (importBtn && importInput) {
            importBtn.addEventListener('click', function() { importInput.click(); });
            importInput.addEventListener('change', function(e) { if (e.target.files[0]) { importJSON(e.target.files[0]); e.target.value = ''; } });
        }

        var exitFocusBtn = document.getElementById('exitFocusBtn');
        if (exitFocusBtn) { exitFocusBtn.addEventListener('click', function() { document.body.classList.remove('focus-mode'); }); }

        buildColorPalette('fillColorGrid', 'fillColorCustom', setFillColor);
        buildColorPalette('bgColorGrid', 'bgColorCustom', setBackgroundColor);
        buildColorPalette('canvasBgGrid', 'canvasBgCustom', setCanvasBgColor);

        setupColorDropdown('fillColorContainer', 'fillColorPicker');
        setupColorDropdown('bgColorContainer', 'bgColorPicker');
        setupColorDropdown('canvasBgContainer', 'canvasBgPicker');

        var fontSizeItems = document.querySelectorAll('[data-fontsize]');
        for (var fi = 0; fi < fontSizeItems.length; fi++) {
            fontSizeItems[fi].addEventListener('click', function() {
                setFontSize(this.dataset.fontsize);
                updateFontSizeCheckmark(parseInt(this.dataset.fontsize));
                document.getElementById('fontSizeContainer').classList.remove('open');
            });
        }

        var lineHeightItems = document.querySelectorAll('[data-lineheight]');
        for (var lh = 0; lh < lineHeightItems.length; lh++) {
            lineHeightItems[lh].addEventListener('click', function() {
                setLineHeight(this.dataset.lineheight);
                updateLineHeightCheckmark(parseFloat(this.dataset.lineheight));
                document.getElementById('lineHeightContainer').classList.remove('open');
            });
        }

        var transformItems = document.querySelectorAll('[data-transform]');
        for (var tr = 0; tr < transformItems.length; tr++) {
            transformItems[tr].addEventListener('click', function() {
                transformText(this.dataset.transform);
                document.getElementById('textTransformContainer').classList.remove('open');
            });
        }

        var dropdowns = document.querySelectorAll('.dropdown-container:not(#fillColorContainer):not(#bgColorContainer):not(#canvasBgContainer)');
        for (var d = 0; d < dropdowns.length; d++) {
            var container = dropdowns[d];
            var btn = container.querySelector('.tool-btn');
            if (btn) {
                btn.addEventListener('click', function(c) {
                    return function(e) {
                        e.stopPropagation();
                        var popups = document.querySelectorAll('.color-picker-popup.show');
                        for (var p = 0; p < popups.length; p++) { popups[p].classList.remove('show'); }
                        c.classList.toggle('open');
                    };
                }(container));
            }
            container.addEventListener('click', function(e) { e.stopPropagation(); });
        }

        document.addEventListener('click', function() {
            var containers = document.querySelectorAll('.dropdown-container.open');
            for (var c = 0; c < containers.length; c++) { containers[c].classList.remove('open'); }
            var popups = document.querySelectorAll('.color-picker-popup.show');
            for (var p = 0; p < popups.length; p++) { popups[p].classList.remove('show'); }
        });

        window.addEventListener('resize', function() {
            if (canvas && container && isInitialized) {
                canvas.setWidth(container.clientWidth);
                canvas.setHeight(container.clientHeight);
                canvas.renderAll();
            }
        });

        window.addEventListener('beforeunload', function(e) {
            if (hasUnsavedChanges) {
                e.preventDefault();
                e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
                return e.returnValue;
            }
        });
    }

    function setupColorDropdown(containerId, pickerId) {
        var container = document.getElementById(containerId);
        var picker = document.getElementById(pickerId);
        if (!container || !picker) return;
        var btn = container.querySelector('.tool-btn');
        if (!btn) return;
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            var popups = document.querySelectorAll('.color-picker-popup.show');
            for (var p = 0; p < popups.length; p++) { if (popups[p] !== picker) popups[p].classList.remove('show'); }
            var containers = document.querySelectorAll('.dropdown-container.open');
            for (var c = 0; c < containers.length; c++) { if (containers[c] !== container) containers[c].classList.remove('open'); }
            picker.classList.toggle('show');
        });
        picker.addEventListener('click', function(e) { e.stopPropagation(); });
    }

    function init() {
        console.log('Initializing Restudio Documents...');
        initCanvas();
        setupEventListeners();
        setupKeyboardShortcuts();
        updateZoomDisplay();
        updateUndoRedoButtons();
        if (fillColorBtn) fillColorBtn.disabled = true;
        if (bgColorBtn) bgColorBtn.disabled = true;
        console.log('Restudio Documents initialized successfully');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
