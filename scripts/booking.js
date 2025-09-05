(function(){
  "use strict";

  const dateInput = document.getElementById("date");
  const slotsContainer = document.getElementById("slots");
  const timeHidden = document.getElementById("time");
  const form = document.getElementById("booking-form");
  const result = document.getElementById("result");

  // Yekaterinburg time utilities (UTC+5, no DST assumed)
  const YEKATERINBURG_OFFSET_MINUTES = 5 * 60;

  function getTodayYekaterinburgDate() {
    const nowUtcMs = Date.now();
    const yektMs = nowUtcMs + YEKATERINBURG_OFFSET_MINUTES * 60 * 1000;
    const d = new Date(yektMs);
    // Return date parts in YEKT
    return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  }

  function toYekaterinburgDate(date) {
    // Normalize arbitrary Date to YEKT wall time date (yyyy-mm-dd)
    const utcMs = date.getTime();
    const yekt = new Date(utcMs + YEKATERINBURG_OFFSET_MINUTES * 60 * 1000);
    const yyyy = yekt.getUTCFullYear();
    const mm = String(yekt.getUTCMonth() + 1).padStart(2, "0");
    const dd = String(yekt.getUTCDate()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd}`;
  }

  function parseDateInputValue(value) {
    
    const [y,m,d] = value.split("-").map(Number);
    
    const yektMidnightUtcMs = Date.UTC(y, m - 1, d) - YEKATERINBURG_OFFSET_MINUTES * 60 * 1000;
    return new Date(yektMidnightUtcMs);
  }

  function generateHalfHourSlotsForDate(yektDateUtc) {
    
    const startMinutes = 9 * 60; // 09:00
    const endMinutes = 18 * 60;  // 18:00 (exclusive)

    const slots = [];
    for (let minutes = startMinutes; minutes < endMinutes; minutes += 30) {
      const slotUtcMs = yektDateUtc.getTime() + (minutes - YEKATERINBURG_OFFSET_MINUTES) * 60 * 1000;
      
      const display = minutesToLabel(minutes);
      slots.push({ utc: new Date(slotUtcMs), label: display });
    }
    return slots;
  }

  function minutesToLabel(totalMinutes) {
    const hh = String(Math.floor(totalMinutes / 60)).padStart(2, "0");
    const mm = String(totalMinutes % 60).padStart(2, "0");
    return `${hh}:${mm}`;
  }

  function clearSlots() { slotsContainer.innerHTML = ""; }

  // Validation functions
  function validateName(name) {
    const trimmed = name.trim();
    if (!trimmed) return { valid: false, message: "Имя обязательно" };
    if (trimmed.length < 2) return { valid: false, message: "Имя должно содержать минимум 2 символа" };
    if (!/^[а-яёА-ЯЁa-zA-Z\s\-]+$/.test(trimmed)) return { valid: false, message: "Имя может содержать только буквы, пробелы и дефисы" };
    return { valid: true };
  }

  function validatePhone(phone) {
    const trimmed = phone.trim();
    if (!trimmed) return { valid: false, message: "Телефон обязателен" };
    
    
    const formattedRegex = /^\+7 \(\d{3}\) \d{3}-\d{2}-\d{2}$/;
    if (formattedRegex.test(trimmed)) return { valid: true };
    
    
    const digits = trimmed.replace(/\D/g, '');
    if (digits.length === 11 && digits.startsWith('7')) return { valid: true };
    if (digits.length === 10 && (trimmed.includes('+7') || trimmed.includes('8'))) return { valid: true };
    
    return { valid: false, message: "Введите корректный номер телефона" };
  }

  function applyPhoneMask(value) {
    
    let digits = value.replace(/\D/g, '');
    
    
    if (digits.startsWith('8')) {
      digits = '7' + digits.slice(1);
    }
    
    
    if (digits.length > 0 && !digits.startsWith('7')) {
      digits = '7' + digits;
    }
    
    
    digits = digits.slice(0, 11);
    
    
    if (digits.length === 0) return '';
    if (digits.length === 1) return '+7';
    if (digits.length <= 4) return `+7 (${digits.slice(1)}`;
    if (digits.length <= 7) return `+7 (${digits.slice(1, 4)}) ${digits.slice(4)}`;
    if (digits.length <= 9) return `+7 (${digits.slice(1, 4)}) ${digits.slice(4, 7)}-${digits.slice(7)}`;
    return `+7 (${digits.slice(1, 4)}) ${digits.slice(4, 7)}-${digits.slice(7, 9)}-${digits.slice(9)}`;
  }

  function showFieldError(fieldId, message) {
    const field = document.getElementById(fieldId);
    const existingError = field.parentNode.querySelector('.field-error');
    if (existingError) existingError.remove();
    
    if (message) {
      const errorDiv = document.createElement('div');
      errorDiv.className = 'field-error';
      errorDiv.textContent = message;
      errorDiv.style.color = '#ff6b6b';
      errorDiv.style.fontSize = '12px';
      errorDiv.style.marginTop = '4px';
      field.parentNode.appendChild(errorDiv);
      field.style.borderColor = '#ff6b6b';
    } else {
      field.style.borderColor = '';
    }
  }

  function renderSlots(slots, isToday) {
    clearSlots();
    const nowUtc = Date.now();

    slots.forEach((slot) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "slot";
      btn.textContent = slot.label + " EKB";

      
      if (isToday && slot.utc.getTime() <= nowUtc) {
        btn.setAttribute("disabled", "true");
      }

      btn.addEventListener("click", () => {
        
        [...slotsContainer.querySelectorAll(".slot[selected]")].forEach(el => el.removeAttribute("selected"));
        btn.setAttribute("selected", "true");
        timeHidden.value = btn.textContent.replace(" EKB", "");
        result.textContent = "";
      });

      slotsContainer.appendChild(btn);
    });
  }

  function initDate() {
    const todayYekt = getTodayYekaterinburgDate();
    const yyyyMmDd = toYekaterinburgDate(todayYekt);
    dateInput.min = yyyyMmDd;
    dateInput.value = yyyyMmDd;
  }

  function refreshSlots() {
    const selected = parseDateInputValue(dateInput.value);
    const today = getTodayYekaterinburgDate();
    const isToday = toYekaterinburgDate(selected) === toYekaterinburgDate(today);
    const slots = generateHalfHourSlotsForDate(selected);
    renderSlots(slots, isToday);
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();

    const dateVal = dateInput.value;
    const timeVal = timeHidden.value;
    const name = document.getElementById("name").value;
    const phone = document.getElementById("phone").value;

    // Validate inputs
    const nameValidation = validateName(name);
    const phoneValidation = validatePhone(phone);
    
    showFieldError('name', nameValidation.valid ? '' : nameValidation.message);
    showFieldError('phone', phoneValidation.valid ? '' : phoneValidation.message);

    if (!nameValidation.valid || !phoneValidation.valid) {
      result.textContent = "Пожалуйста, исправьте ошибки в полях";
      return;
    }

    if (!dateVal || !timeVal) {
      result.textContent = "Пожалуйста, выберите дату и время.";
      return;
    }

    
    (async () => {
      result.textContent = "Отправка...";
      try {
        const r = await fetch('/api/bookings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ date: dateVal, time: timeVal, name, phone })
        });
        if (!r.ok) throw new Error('http');
        const [y,m,d] = dateVal.split('-');
        const dotted = `${d}.${m}.${y}`;
        result.textContent = `Заявка отправлена: ${dotted} ${timeVal} (EKB, Екатеринбург)`;
        form.reset();
        initDate();
        refreshSlots();
      } catch (err) {
        result.textContent = "Ошибка отправки. Повторите попытку.";
      }
    })();
  });

  dateInput.addEventListener("change", () => {
    timeHidden.value = "";
    refreshSlots();
  });

  // Real-time validation
  document.getElementById("name").addEventListener("input", (e) => {
    const validation = validateName(e.target.value);
    showFieldError('name', validation.valid ? '' : validation.message);
  });

  document.getElementById("phone").addEventListener("input", (e) => {
    const newValue = applyPhoneMask(e.target.value);
    e.target.value = newValue;
    
    const validation = validatePhone(e.target.value);
    showFieldError('phone', validation.valid ? '' : validation.message);
  });

  
  const openCalendar = () => {
    try {
      if (typeof dateInput.showPicker === "function") {
        dateInput.showPicker();
      }
    } catch(_) { /* ignore */ }
  };
  dateInput.addEventListener("click", openCalendar);
  dateInput.addEventListener("focus", openCalendar);
  dateInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      openCalendar();
    }
  });

  // Bootstrap
  initDate();
  refreshSlots();
})();


