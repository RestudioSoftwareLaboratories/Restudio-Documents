// ========== SECURITY UTILITIES ==========

// 1. Sanitization - منع هجمات XSS
function sanitizeText(text) {
    if (text === null || text === undefined) return '';
    if (typeof text !== 'string') return String(text);
    
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;',
        '=': '&#x3D;',
        '`': '&#x60;'
    };
    return text.replace(/[&<>"'/=`]/g, function(match) {
        return map[match];
    });
}

// التحقق من صحة النص (منع الأكواد الضارة)
function isValidText(text) {
    if (typeof text !== 'string') return false;
    const dangerousPatterns = [
        /javascript:/i,
        /on\w+\s*=/i,
        /<script/i,
        /<iframe/i,
        /<object/i,
        /<embed/i,
        /data:text\/html/i,
        /vbscript:/i
    ];
    return !dangerousPatterns.some(pattern => pattern.test(text));
}

// 2. التحقق من صحة الملفات المستوردة
function validateREDCFile(data) {
    if (!data || typeof data !== 'object') {
        throw new Error('Invalid file format: Data is not an object');
    }
    
    // التحقق من حجم البيانات
    const MAX_FILE_SIZE_MB = 20;
    const jsonString = JSON.stringify(data);
    const sizeInMB = new Blob([jsonString]).size / (1024 * 1024);
    if (sizeInMB > MAX_FILE_SIZE_MB) {
        throw new Error(`File too large: ${sizeInMB.toFixed(2)}MB (max ${MAX_FILE_SIZE_MB}MB)`);
    }
    
    // التحقق من وجود objects ونسقها
    if (data.objects && !Array.isArray(data.objects)) {
        throw new Error('Invalid file: Objects must be an array');
    }
    
    // التحقق من صحة كل object
    if (data.objects) {
        for (let i = 0; i < data.objects.length; i++) {
            const obj = data.objects[i];
            if (!obj || typeof obj !== 'object') {
                throw new Error(`Invalid object at index ${i}`);
            }
            // التحقق من type مسموح به
            const allowedTypes = ['textbox', 'rect', 'circle', 'image', 'group'];
            if (obj.type && !allowedTypes.includes(obj.type)) {
                throw new Error(`Invalid object type: ${obj.type}`);
            }
            // تطهير النصوص في الملف المستورد
            if (obj.type === 'textbox' && obj.text) {
                if (!isValidText(obj.text)) {
                    throw new Error(`Suspicious content detected in text object`);
                }
                obj.text = sanitizeText(obj.text);
            }
        }
    }
    
    return true;
}

// 3. التحقق من الحدود
function validateCanvasAccess() {
    if (!canvas) {
        console.warn('Canvas not initialized');
        return false;
    }
    return true;
}

function getActiveObjectSafe() {
    if (!validateCanvasAccess()) return null;
    return canvas.getActiveObject();
}

function getActiveObjectsSafe() {
    if (!validateCanvasAccess()) return [];
    return canvas.getActiveObjects();
}

// ========== MAIN APPLICATION ==========

(function() {
    const container = document.getElementById('fabric-canvas-container');
    const zoomLevelDisplay = document.getElementById('zoomLevelDisplay');
    const undoBtn = document.querySelector('[data-action="undo"]');
    const redoBtn = document.querySelector('[data-action="redo"]');
    const boldBtn = document.querySelector('[data-action="bold"]');
    const italicBtn = document.querySelector('[data-action="italic"]');
    const underlineBtn = document.querySelector('[data-action="underline"]');
    const alignLeftBtn = document.querySelector('[data-action="alignLeft"]');
    const alignCenterBtn = document.querySelector('[data-action="alignCenter"]');
    const alignRightBtn = document.querySelector('[data-action="alignRight"]');
    const fillColorBtn = document.getElementById('fillColorBtn');
    const bgColorBtn = document.getElementById('bgColorBtn');

    let canvas;
    let historyStack = [],
        historyIndex = -1;
    let zoomLevel = 1;
    let historySaveTimer = null;
    let hasUnsavedChanges = false;

    // ============ Refresh Warning ============
    window.addEventListener('beforeunload', function(e) {
        if (hasUnsavedChanges) {
            e.preventDefault();
            e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
            return e.returnValue;
        }
    });

    // Track changes
    function markAsChanged() {
        hasUnsavedChanges = true;
    }

    function saveHistoryState() {
        if (!canvas) return;
        try {
            const state = JSON.stringify(canvas.toJSON(['id', 'customType']));
            if (historyStack.length === 0 || historyStack[historyIndex] !== state) {
                historyStack = historyStack.slice(0, historyIndex + 1);
                historyStack.push(state);
                historyIndex++;
                markAsChanged();
            }
            updateUndoRedoButtons();
        } catch (err) {
            console.error('Error saving history:', err);
        }
    }

    function scheduleHistorySave() {
        if (historySaveTimer) clearTimeout(historySaveTimer);
        historySaveTimer = setTimeout(saveHistoryState, 150);
    }

    function resetHistoryFromCurrentCanvas() {
        if (!canvas) return;
        try {
            historyStack = [];
            historyIndex = -1;
            const state = JSON.stringify(canvas.toJSON(['id', 'customType']));
            historyStack.push(state);
            historyIndex = 0;
            updateUndoRedoButtons();
        } catch (err) {
            console.error('Error resetting history:', err);
        }
    }

    function updateUndoRedoButtons() {
        if (undoBtn) undoBtn.disabled = (historyIndex <= 0);
        if (redoBtn) redoBtn.disabled = (historyIndex >= historyStack.length - 1);
    }

    function undo() {
        if (historyIndex > 0 && canvas) {
            historyIndex--;
            loadHistoryState();
        }
    }

    function redo() {
        if (historyIndex < historyStack.length - 1 && canvas) {
            historyIndex++;
            loadHistoryState();
        }
    }

    function loadHistoryState() {
        if (!canvas || historyStack.length === 0) return;
        try {
            canvas.loadFromJSON(historyStack[historyIndex], () => {
                canvas.renderAll();
                updateUndoRedoButtons();
                updateStyleButtonsState();
            });
        } catch (err) {
            console.error('Error loading history state:', err);
        }
    }

    function isImage(obj) {
        return obj && obj.type === 'image';
    }

    function updateStyleButtonsState() {
        const activeObj = getActiveObjectSafe();
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

        const img = isImage(activeObj);

        if (activeObj.type === 'textbox') {
            if (boldBtn) boldBtn.classList.toggle('active', activeObj.fontWeight === 'bold');
            if (italicBtn) italicBtn.classList.toggle('active', activeObj.fontStyle === 'italic');
            if (underlineBtn) underlineBtn.classList.toggle('active', !!activeObj.underline);
            const align = activeObj.textAlign || 'left';
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
        document.querySelectorAll('#fontSizeMenu .dropdown-item').forEach(item => {
            const check = item.querySelector('.check-icon');
            if (check) {
                check.style.display = (fontSize && parseInt(item.dataset.fontsize) === fontSize) ?
                    'inline' : 'none';
            }
        });
    }

    function updateLineHeightCheckmark(lineHeight) {
        document.querySelectorAll('#lineHeightMenu .dropdown-item').forEach(item => {
            const check = item.querySelector('.check-icon');
            if (check) {
                const val = parseFloat(item.dataset.lineheight);
                check.style.display = (lineHeight && Math.abs(val - lineHeight) < 0.01) ?
                    'inline' : 'none';
            }
        });
    }

    const presetColors = [
        '#ffffff', '#000000', '#e74c3c', '#e67e22', '#f1c40f', '#2ecc71',
        '#1abc9c', '#3498db', '#9b59b6', '#ecf0f1', '#c0392b', '#2980b9',
        '#8e44ad', '#2c3e50', '#16a085', '#27ae60', '#f39c12', '#d35400',
        '#7f8c8d', '#bdc3c7', '#34495e', '#95a5a6'
    ];

    function buildColorPalette(gridId, customInputId, callback) {
        const grid = document.getElementById(gridId);
        if (!grid) return;
        grid.innerHTML = '';
        presetColors.forEach(color => {
            const swatch = document.createElement('div');
            swatch.className = 'color-swatch';
            swatch.style.backgroundColor = color;
            swatch.addEventListener('click', (e) => {
                e.stopPropagation();
                callback(color);
                const customInput = document.getElementById(customInputId);
                if (customInput) customInput.value = color;
                const popup = grid.closest('.color-picker-popup');
                if (popup) popup.classList.remove('show');
            });
            grid.appendChild(swatch);
        });
        const customInput = document.getElementById(customInputId);
        if (customInput) {
            customInput.addEventListener('input', (e) => {
                callback(e.target.value);
            });
        }
    }

    function initCanvas() {
        const existingCanvas = document.getElementById('fabric-canvas');
        if (existingCanvas) existingCanvas.remove();
        const newCanvasElem = document.createElement('canvas');
        newCanvasElem.id = 'fabric-canvas';
        newCanvasElem.width = container.clientWidth || 900;
        newCanvasElem.height = container.clientHeight || 600;
        container.innerHTML = '';
        container.appendChild(newCanvasElem);
        canvas = new fabric.Canvas('fabric-canvas', {
            preserveObjectStacking: true,
            selection: true,
            backgroundColor: '#2b2b2b'
        });
        canvas.setWidth(container.clientWidth);
        canvas.setHeight(container.clientHeight);
        canvas.renderAll();
        canvas.on('object:added', () => scheduleHistorySave());
        canvas.on('object:modified', () => scheduleHistorySave());
        canvas.on('object:removed', () => scheduleHistorySave());
        canvas.on('selection:created', () => updateStyleButtonsState());
        canvas.on('selection:updated', () => updateStyleButtonsState());
        canvas.on('selection:cleared', () => {
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
    initCanvas();
    resetHistoryFromCurrentCanvas();

    window.addEventListener('resize', () => {
        if (canvas && container) {
            canvas.setWidth(container.clientWidth);
            canvas.setHeight(container.clientHeight);
            canvas.renderAll();
        }
    });

    function newCanvas() {
        if (!canvas) return;
        if (hasUnsavedChanges) {
            if (!confirm('You have unsaved changes. Are you sure you want to create a new canvas?')) {
                return;
            }
        }
        canvas.clear();
        canvas.backgroundColor = '#2b2b2b';
        zoomLevel = 1;
        canvas.setZoom(1);
        canvas.renderAll();
        resetHistoryFromCurrentCanvas();
        updateZoomDisplay();
        hasUnsavedChanges = false;
    }

    function addTextBox() {
        if (!canvas) return;
        const textbox = new fabric.Textbox('New Text', {
            left: 100,
            top: 100,
            width: 200,
            fontSize: 24,
            fill: '#ffffff',
            fontFamily: 'Segoe UI',
            hasControls: true,
            hasBorders: true
        });
        canvas.add(textbox);
        canvas.setActiveObject(textbox);
        canvas.renderAll();
        scheduleHistorySave();
    }

    function addRectangle() {
        if (!canvas) return;
        const rect = new fabric.Rect({
            left: 150,
            top: 150,
            width: 120,
            height: 80,
            fill: '#3498db',
            stroke: '#ffffff',
            strokeWidth: 2
        });
        canvas.add(rect);
        canvas.setActiveObject(rect);
        canvas.renderAll();
        scheduleHistorySave();
    }

    function addCircle() {
        if (!canvas) return;
        const circle = new fabric.Circle({
            left: 200,
            top: 200,
            radius: 50,
            fill: '#e67e22',
            stroke: '#fff',
            strokeWidth: 2
        });
        canvas.add(circle);
        canvas.setActiveObject(circle);
        canvas.renderAll();
        scheduleHistorySave();
    }

    function addImageFromFile() {
        document.getElementById('imageFileInput').click();
    }

    function addQRCode() {
        if (!canvas) return;
        const text = prompt('Enter text or URL for the QR code:', 'https://restudio.com');
        if (!text || !text.trim()) return;
        
        // التحقق من صحة النص
        const sanitizedText = sanitizeText(text.trim());
        if (!isValidText(sanitizedText)) {
            alert('Invalid text detected. Please enter a valid URL or text.');
            return;
        }
        
        const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(sanitizedText)}`;
        fabric.Image.fromURL(qrUrl, (img) => {
            if (!canvas) return;
            img.set({
                left: (canvas.width - img.width * img.scaleX) / 2,
                top: (canvas.height - img.height * img.scaleY) / 2
            });
            canvas.add(img);
            canvas.setActiveObject(img);
            canvas.renderAll();
            scheduleHistorySave();
        }, { crossOrigin: 'anonymous' });
    }

    function handleImageFileSelect(event) {
        const file = event.target.files[0];
        if (!file) return;
        if (!file.type.startsWith('image/')) {
            alert('Please select a valid image file.');
            event.target.value = '';
            return;
        }
        
        // التحقق من حجم الملف (حد أقصى 10MB)
        const MAX_IMAGE_SIZE = 10 * 1024 * 1024;
        if (file.size > MAX_IMAGE_SIZE) {
            alert(`Image file too large: ${(file.size / 1024 / 1024).toFixed(2)}MB (max 10MB)`);
            event.target.value = '';
            return;
        }
        
        const reader = new FileReader();
        reader.onload = function(e) {
            if (!canvas) return;
            fabric.Image.fromURL(e.target.result, (img) => {
                if (!canvas) return;
                const maxWidth = canvas.width * 0.6;
                const maxHeight = canvas.height * 0.6;
                if (img.width > maxWidth || img.height > maxHeight) {
                    const scale = Math.min(maxWidth / img.width, maxHeight / img.height);
                    img.scale(scale);
                } else {
                    img.scale(1);
                }
                img.set({
                    left: (canvas.width - img.width * img.scaleX) / 2,
                    top: (canvas.height - img.height * img.scaleY) / 2
                });
                canvas.add(img);
                canvas.setActiveObject(img);
                canvas.renderAll();
                scheduleHistorySave();
            }, { crossOrigin: 'anonymous' });
        };
        reader.onerror = () => alert('Failed to load image file.');
        reader.readAsDataURL(file);
        event.target.value = '';
    }

    function deleteSelected() {
        if (!canvas) return;
        const active = canvas.getActiveObjects();
        if (active.length) {
            active.forEach(obj => canvas.remove(obj));
            canvas.discardActiveObject();
            canvas.renderAll();
            scheduleHistorySave();
        }
    }

    function bringForward() {
        if (!canvas) return;
        const obj = getActiveObjectSafe();
        if (obj) {
            canvas.bringForward(obj);
            canvas.renderAll();
            scheduleHistorySave();
        }
    }

    function sendBackward() {
        if (!canvas) return;
        const obj = getActiveObjectSafe();
        if (obj) {
            canvas.sendBackwards(obj);
            canvas.renderAll();
            scheduleHistorySave();
        }
    }

    function applyToSelected(callback) {
        if (!canvas) return;
        const actives = canvas.getActiveObjects();
        if (actives.length) {
            actives.forEach(obj => callback(obj));
            canvas.renderAll();
            scheduleHistorySave();
            updateStyleButtonsState();
        }
    }

    function setBold() {
        applyToSelected(obj => {
            if (obj.type === 'textbox') {
                obj.fontWeight = (obj.fontWeight === 'bold') ? 'normal' : 'bold';
            }
        });
    }

    function setItalic() {
        applyToSelected(obj => {
            if (obj.type === 'textbox') {
                obj.fontStyle = (obj.fontStyle === 'italic') ? 'normal' : 'italic';
            }
        });
    }

    function setUnderline() {
        applyToSelected(obj => {
            if (obj.type === 'textbox') {
                obj.underline = !obj.underline;
            }
        });
    }

    function setFontSize(size) {
        applyToSelected(obj => {
            if (obj.fontSize !== undefined) obj.fontSize = parseInt(size);
        });
        document.getElementById('fontSizeContainer').classList.remove('open');
    }

    function setLineHeight(height) {
        applyToSelected(obj => {
            if (obj.lineHeight !== undefined) obj.lineHeight = parseFloat(height);
        });
        document.getElementById('lineHeightContainer').classList.remove('open');
    }

    function setFillColor(color) {
        applyToSelected(obj => {
            if (obj.type !== 'image') {
                obj.set('fill', color);
            }
        });
    }

    function setBackgroundColor(color) {
        applyToSelected(obj => {
            if (obj.type === 'textbox') {
                obj.set('backgroundColor', color);
            }
        });
    }

    function setTextAlign(align) {
        applyToSelected(obj => {
            if (obj.textAlign !== undefined) obj.textAlign = align;
        });
    }

    function setCanvasBgColor(color) {
        if (!canvas) return;
        canvas.setBackgroundColor(color, () => canvas.renderAll());
        markAsChanged();
    }

    function increaseIndent() {
        applyToSelected(obj => {
            if (obj.type === 'textbox') {
                obj.text = '    ' + obj.text;
            }
        });
    }

    function decreaseIndent() {
        applyToSelected(obj => {
            if (obj.type === 'textbox') {
                const trimmed = obj.text.replace(/^ {1,4}/, '');
                obj.text = trimmed;
            }
        });
    }

    function transformText(type) {
        applyToSelected(obj => {
            if (obj.type === 'textbox') {
                switch (type) {
                    case 'uppercase':
                        obj.text = obj.text.toUpperCase();
                        break;
                    case 'lowercase':
                        obj.text = obj.text.toLowerCase();
                        break;
                    case 'capitalize':
                        obj.text = obj.text.replace(/\b\w/g, c => c.toUpperCase());
                        break;
                }
            }
        });
        document.getElementById('textTransformContainer').classList.remove('open');
    }

    function updateZoomDisplay() {
        zoomLevelDisplay.textContent = Math.round(zoomLevel * 100) + '%';
    }

    function zoomIn() {
        if (!canvas) return;
        zoomLevel = Math.min(2, zoomLevel + 0.1);
        canvas.setZoom(zoomLevel);
        canvas.renderAll();
        updateZoomDisplay();
    }

    function zoomOut() {
        if (!canvas) return;
        zoomLevel = Math.max(0.5, zoomLevel - 0.1);
        canvas.setZoom(zoomLevel);
        canvas.renderAll();
        updateZoomDisplay();
    }

    function exportAsREDC() {
        if (!canvas) return;
        try {
            const dataStr = JSON.stringify(canvas.toJSON(['id']), null, 2);
            const blob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'canvas.redc';
            a.click();
            URL.revokeObjectURL(url);
            hasUnsavedChanges = false;
        } catch (err) {
            alert('Error exporting file: ' + err.message);
        }
    }

    function importJSON(file) {
        if (!canvas) return;
        if (hasUnsavedChanges) {
            if (!confirm('Importing will replace the current canvas content. Are you sure?')) return;
        }
        
        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const json = JSON.parse(e.target.result);
                
                // التحقق من صحة الملف
                validateREDCFile(json);
                
                canvas.loadFromJSON(json, () => {
                    canvas.renderAll();
                    resetHistoryFromCurrentCanvas();
                    updateZoomDisplay();
                    hasUnsavedChanges = false;
                });
            } catch (err) {
                alert('Import failed: ' + err.message);
            }
        };
        reader.onerror = () => alert('Error reading file.');
        reader.readAsText(file);
    }

    const actionsMap = {
        newDoc: newCanvas,
        undo,
        redo,
        deleteSelected,
        addText: addTextBox,
        addImage: addImageFromFile,
        addRectangle,
        addCircle,
        addQR: addQRCode,
        bold: setBold,
        italic: setItalic,
        underline: setUnderline,
        alignLeft: () => setTextAlign('left'),
        alignCenter: () => setTextAlign('center'),
        alignRight: () => setTextAlign('right'),
        bringForward,
        sendBackward,
        zoomIn,
        zoomOut,
        focusMode: () => document.body.classList.toggle('focus-mode'),
        exportRedc: exportAsREDC,
        indentInc: increaseIndent,
        indentDec: decreaseIndent
    };

    document.getElementById('toolbar').addEventListener('click', (e) => {
        const btn = e.target.closest('.tool-btn');
        if (!btn || btn.closest('.dropdown-container')) return;
        const action = btn.dataset.action;
        if (action && actionsMap[action]) actionsMap[action]();
    });

    document.getElementById('imageFileInput').addEventListener('change', handleImageFileSelect);

    document.querySelectorAll('[data-fontsize]').forEach(el => {
        el.addEventListener('click', () => {
            setFontSize(el.dataset.fontsize);
            updateFontSizeCheckmark(parseInt(el.dataset.fontsize));
        });
    });

    document.querySelectorAll('[data-lineheight]').forEach(el => {
        el.addEventListener('click', () => {
            setLineHeight(el.dataset.lineheight);
            updateLineHeightCheckmark(parseFloat(el.dataset.lineheight));
        });
    });

    document.querySelectorAll('[data-transform]').forEach(el => {
        el.addEventListener('click', () => transformText(el.dataset.transform));
    });

    buildColorPalette('fillColorGrid', 'fillColorCustom', setFillColor);
    buildColorPalette('bgColorGrid', 'bgColorCustom', setBackgroundColor);
    buildColorPalette('canvasBgGrid', 'canvasBgCustom', setCanvasBgColor);

    function setupColorDropdown(containerId, pickerId) {
        const container = document.getElementById(containerId);
        const picker = document.getElementById(pickerId);
        if (!container || !picker) return;
        const btn = container.querySelector('.tool-btn');
        if (!btn) return;
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            document.querySelectorAll('.color-picker-popup.show').forEach(p => {
                if (p !== picker) p.classList.remove('show');
            });
            document.querySelectorAll('.dropdown-container.open').forEach(d => {
                if (d !== container) d.classList.remove('open');
            });
            picker.classList.toggle('show');
        });
        picker.addEventListener('click', (e) => e.stopPropagation());
    }

    setupColorDropdown('fillColorContainer', 'fillColorPicker');
    setupColorDropdown('bgColorContainer', 'bgColorPicker');
    setupColorDropdown('canvasBgContainer', 'canvasBgPicker');

    document.querySelectorAll(
            '.dropdown-container:not(#fillColorContainer):not(#bgColorContainer):not(#canvasBgContainer)'
        )
        .forEach(cont => {
            const btn = cont.querySelector('.tool-btn');
            if (btn) {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    document.querySelectorAll('.color-picker-popup.show').forEach(p => p
                        .classList.remove('show'));
                    cont.classList.toggle('open');
                });
            }
            cont.addEventListener('click', (e) => e.stopPropagation());
        });

    document.addEventListener('click', () => {
        document.querySelectorAll('.dropdown-container.open').forEach(c => c.classList.remove('open'));
        document.querySelectorAll('.color-picker-popup.show').forEach(p => p.classList.remove('show'));
    });

    document.getElementById('importJsonBtn').addEventListener('click', () => {
        document.getElementById('importFileInput').click();
    });

    document.getElementById('importFileInput').addEventListener('change', (e) => {
        if (e.target.files[0]) {
            importJSON(e.target.files[0]);
            e.target.value = '';
        }
    });

    document.getElementById('exitFocusBtn').addEventListener('click', () => document.body.classList.remove(
        'focus-mode'));

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && document.body.classList.contains('focus-mode')) {
            document.body.classList.remove('focus-mode');
        }
        if (e.ctrlKey && e.key === 'z') {
            e.preventDefault();
            undo();
        }
        if (e.ctrlKey && e.key === 'y') {
            e.preventDefault();
            redo();
        }
        if (e.key === 'Delete' && !e.ctrlKey && !e.altKey && document.activeElement === document.body) {
            e.preventDefault();
            deleteSelected();
        }
    });

    updateZoomDisplay();
    updateUndoRedoButtons();
    if (fillColorBtn) fillColorBtn.disabled = true;
    if (bgColorBtn) bgColorBtn.disabled = true;
})();
