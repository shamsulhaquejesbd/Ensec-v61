import React, { useEffect, useRef, useState } from 'react';
import {
  AlertCircle,
  BatteryCharging,
  CheckCircle2,
  ImagePlus,
  Lock,
  Palette,
  RefreshCw,
  RotateCcw,
  Save,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  Upload,
} from 'lucide-react';
import { useERP } from '../../context/ERPContext.tsx';
import { useSystemSettings } from '../../context/SystemSettingsContext.tsx';
import { apiRequest } from '../../lib/apiClient.ts';
import {
  canAccessSystemSettings,
  canManageSystemBranding,
} from '../../types/pagePermissions.ts';

type SettingsSectionId = 'branding';

interface SettingsSectionDefinition {
  id: SettingsSectionId;
  label: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
}

const SETTINGS_SECTIONS: SettingsSectionDefinition[] = [
  {
    id: 'branding',
    label: 'System Branding',
    description: 'Software name, logo / icon, and global platform identity',
    icon: Palette,
  },
];

const MAX_LOGO_FILE_BYTES = 1_500_000; // 1.5 MB
const ALLOWED_IMAGE_MIME_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/jpg',
  'image/webp',
  'image/svg+xml',
  'image/gif',
  'image/x-icon',
  'image/vnd.microsoft.icon',
]);

export const SettingsPage: React.FC = () => {
  const { currentUser } = useERP();
  const { branding, updateBranding } = useSystemSettings();

  const canAccess = canAccessSystemSettings(currentUser);
  const canEditBranding = canManageSystemBranding(currentUser);

  const [activeSection, setActiveSection] = useState<SettingsSectionId>('branding');
  const [softwareName, setSoftwareName] = useState<string>(branding.softwareName || 'Ensec');
  const [draftLogoDataUrl, setDraftLogoDataUrl] = useState<string | null>(branding.logoDataUrl);
  const [logoAction, setLogoAction] = useState<'keep' | 'replace' | 'reset'>('keep');
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [updatedByLabel, setUpdatedByLabel] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Sync draft form whenever centralized branding refreshes externally
  useEffect(() => {
    setSoftwareName(branding.softwareName || 'Ensec');
    setDraftLogoDataUrl(branding.logoDataUrl);
    setLogoAction('keep');
    setSelectedFileName(null);
  }, [branding.softwareName, branding.logoDataUrl]);

  // Fetch admin settings audit metadata if authorized
  useEffect(() => {
    if (!canAccess) return;
    let active = true;
    apiRequest<{ ok: boolean; settings?: { branding?: { updatedBy?: string | null } } }>('/api/system/settings')
      .then((res) => {
        if (active && res?.settings?.branding?.updatedBy) {
          setUpdatedByLabel(res.settings.branding.updatedBy);
        }
      })
      .catch(() => {
        // Non-fatal
      });
    return () => {
      active = false;
    };
  }, [canAccess, branding.updatedAt]);

  if (!canAccess) {
    return (
      <div className="p-8 max-w-lg mx-auto mt-10 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-lg text-center space-y-3">
        <div className="w-14 h-14 mx-auto rounded-2xl bg-rose-100 dark:bg-rose-950/60 text-rose-600 dark:text-rose-400 flex items-center justify-center">
          <ShieldAlert className="w-7 h-7" />
        </div>
        <h2 className="text-base font-bold text-slate-900 dark:text-white">
          Admin Authorization Required
        </h2>
        <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
          Only authorized Admin users can access System Settings and modify System Branding.
        </p>
      </div>
    );
  }

  const processLogoFile = (file: File) => {
    if (!canEditBranding) return;
    setFeedback(null);

    if (!ALLOWED_IMAGE_MIME_TYPES.has(file.type.toLowerCase())) {
      setFeedback({
        type: 'error',
        message: 'Unsupported image format. Please upload PNG, JPG, WEBP, SVG, GIF, or ICO.',
      });
      return;
    }

    if (file.size > MAX_LOGO_FILE_BYTES) {
      setFeedback({
        type: 'error',
        message: 'Selected logo exceeds the 1.5 MB size limit. Please choose a smaller image file.',
      });
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const result = typeof reader.result === 'string' ? reader.result : null;
      if (!result || !result.startsWith('data:image/')) {
        setFeedback({
          type: 'error',
          message: 'Could not read the selected image file. Please try another file.',
        });
        return;
      }
      setDraftLogoDataUrl(result);
      setLogoAction('replace');
      setSelectedFileName(file.name);
    };
    reader.onerror = () => {
      setFeedback({
        type: 'error',
        message: 'Failed to read image file from your device.',
      });
    };
    reader.readAsDataURL(file);
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      processLogoFile(file);
    }
    e.target.value = '';
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    if (!canEditBranding) return;
    const file = e.dataTransfer.files?.[0];
    if (file) {
      processLogoFile(file);
    }
  };

  const handleResetLogoToDefault = () => {
    if (!canEditBranding) return;
    setFeedback(null);
    setDraftLogoDataUrl(null);
    setLogoAction('reset');
    setSelectedFileName(null);
  };

  const handleDiscardDraft = () => {
    setFeedback(null);
    setSoftwareName(branding.softwareName || 'Ensec');
    setDraftLogoDataUrl(branding.logoDataUrl);
    setLogoAction('keep');
    setSelectedFileName(null);
  };

  const trimmedSoftwareName = softwareName.trim();
  const hasUnsavedChanges =
    trimmedSoftwareName !== (branding.softwareName || 'Ensec') ||
    logoAction === 'replace' ||
    (logoAction === 'reset' && branding.logoDataUrl !== null);

  const handleSaveBranding = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canEditBranding) return;
    setFeedback(null);

    if (!trimmedSoftwareName) {
      setFeedback({
        type: 'error',
        message: 'Software Name cannot be empty.',
      });
      return;
    }

    if (trimmedSoftwareName.length > 80) {
      setFeedback({
        type: 'error',
        message: 'Software Name must be 80 characters or fewer.',
      });
      return;
    }

    setIsSaving(true);
    try {
      const payload: {
        softwareName: string;
        logoDataUrl?: string | null;
        resetLogo?: boolean;
      } = {
        softwareName: trimmedSoftwareName,
      };

      if (logoAction === 'replace' && draftLogoDataUrl) {
        payload.logoDataUrl = draftLogoDataUrl;
      } else if (logoAction === 'reset') {
        payload.resetLogo = true;
      }

      const saved = await updateBranding(payload);
      setSoftwareName(saved.softwareName);
      setDraftLogoDataUrl(saved.logoDataUrl);
      setLogoAction('keep');
      setSelectedFileName(null);
      setFeedback({
        type: 'success',
        message: `System Branding updated to "${saved.softwareName}" and applied globally across the ERP.`,
      });
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Failed to save System Branding changes.',
      });
    } finally {
      setIsSaving(false);
    }
  };

  const previewSoftwareName = trimmedSoftwareName || 'Ensec';
  const isDefaultEnsecName = previewSoftwareName.toLowerCase() === 'ensec';

  return (
    <div className="space-y-6 pb-10">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-xs">
        <div className="flex items-start gap-3.5">
          <div className="w-11 h-11 rounded-2xl bg-gradient-to-tr from-blue-600 via-indigo-600 to-cyan-500 text-white flex items-center justify-center shadow-md shadow-blue-500/20 shrink-0">
            <Settings className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-lg font-extrabold tracking-tight text-slate-900 dark:text-white">
                Settings
              </h1>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200/70 dark:border-indigo-800">
                <ShieldCheck className="w-3 h-3" />
                System Configuration
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Manage global platform configuration applied across all users, sessions, and portals.
            </p>
          </div>
        </div>

        {branding.updatedAt && (
          <div className="text-right text-[11px] text-slate-500 dark:text-slate-400 shrink-0">
            <div>
              Last updated:{' '}
              <span className="font-semibold text-slate-700 dark:text-slate-200">
                {new Date(branding.updatedAt).toLocaleString()}
              </span>
            </div>
            {updatedByLabel && (
              <div className="text-[10px] text-slate-400">By {updatedByLabel}</div>
            )}
          </div>
        )}
      </div>

      {/* Scalable Two-Column Settings Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Section Selector Rail (Scalable for future settings sections) */}
        <aside className="lg:col-span-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-3 space-y-1.5 shadow-xs">
          <div className="px-2.5 pt-1 pb-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
            Configuration Sections
          </div>
          {SETTINGS_SECTIONS.map((sec) => {
            const Icon = sec.icon;
            const isSelected = activeSection === sec.id;
            return (
              <button
                key={sec.id}
                type="button"
                onClick={() => setActiveSection(sec.id)}
                className={`w-full text-left px-3 py-2.5 rounded-xl transition-all flex items-start gap-2.5 cursor-pointer ${
                  isSelected
                    ? 'bg-blue-600 text-white shadow-xs'
                    : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                <Icon
                  className={`w-4 h-4 mt-0.5 shrink-0 ${
                    isSelected ? 'text-white' : 'text-slate-400'
                  }`}
                />
                <div className="min-w-0">
                  <div className="text-xs font-bold leading-snug">{sec.label}</div>
                  <div
                    className={`text-[10px] leading-snug mt-0.5 ${
                      isSelected ? 'text-blue-100' : 'text-slate-500 dark:text-slate-400'
                    }`}
                  >
                    {sec.description}
                  </div>
                </div>
              </button>
            );
          })}
        </aside>

        {/* Main Configuration Content Area */}
        <section className="lg:col-span-9 space-y-6">
          {activeSection === 'branding' && (
            <form
              onSubmit={handleSaveBranding}
              className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-xs overflow-hidden"
            >
              {/* Section Header */}
              <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-4 bg-slate-50/70 dark:bg-slate-800/40">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-xl bg-blue-100 dark:bg-blue-950/70 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                    <Palette className="w-4 h-4" />
                  </div>
                  <div>
                    <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                      System Branding
                    </h2>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400">
                      Changes automatically update the Sidebar, Login Page, and Browser Title for all users.
                    </p>
                  </div>
                </div>
                {!canEditBranding && (
                  <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-amber-50 dark:bg-amber-950/50 border border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-300 text-[11px] font-semibold">
                    <Lock className="w-3 h-3" />
                    Read-Only
                  </span>
                )}
              </div>

              <div className="p-6 space-y-6">
                {/* Feedback Banner */}
                {feedback && (
                  <div
                    className={`p-3.5 rounded-xl border text-xs flex items-center gap-2.5 ${
                      feedback.type === 'success'
                        ? 'bg-emerald-50 dark:bg-emerald-950/50 border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-200'
                        : 'bg-rose-50 dark:bg-rose-950/50 border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-200'
                    }`}
                  >
                    {feedback.type === 'success' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                    ) : (
                      <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
                    )}
                    <span className="font-medium">{feedback.message}</span>
                  </div>
                )}

                {/* A. Software Name */}
                <div className="space-y-2">
                  <label
                    htmlFor="system-software-name-input"
                    className="block text-xs font-bold text-slate-800 dark:text-slate-200"
                  >
                    Software Name <span className="text-rose-500">*</span>
                  </label>
                  <div className="max-w-lg">
                    <input
                      id="system-software-name-input"
                      name="softwareName"
                      type="text"
                      required
                      maxLength={80}
                      disabled={!canEditBranding || isSaving}
                      value={softwareName}
                      onChange={(e) => {
                        setSoftwareName(e.target.value);
                        if (feedback) setFeedback(null);
                      }}
                      placeholder="Ensec"
                      className="w-full px-3.5 py-2.5 rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white text-sm font-medium focus:outline-none focus:ring-4 focus:ring-blue-500/15 focus:border-blue-600 disabled:opacity-60 transition-all"
                    />
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Default value is <span className="font-semibold">Ensec</span>. Displayed in the Sidebar header, Login page branding title, and browser tab title.
                  </p>
                </div>

                <hr className="border-slate-200 dark:border-slate-800" />

                {/* B. Software Logo / Icon */}
                <div className="space-y-3">
                  <div>
                    <h3 className="text-xs font-bold text-slate-800 dark:text-slate-200">
                      Software Logo / Icon
                    </h3>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                      Upload a custom brand icon or logo from your device. Stored persistently on the server for all users.
                    </p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-12 gap-5 items-stretch">
                    {/* Current / Draft Logo Preview Card */}
                    <div className="md:col-span-4 rounded-2xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 p-4 flex flex-col items-center justify-center text-center gap-3">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                        {logoAction === 'replace'
                          ? 'New Logo Preview'
                          : logoAction === 'reset'
                          ? 'Default Icon Preview'
                          : 'Current Configured Logo'}
                      </span>

                      <div className="w-20 h-20 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 shadow-xs flex items-center justify-center overflow-hidden p-2">
                        {draftLogoDataUrl ? (
                          <img
                            src={draftLogoDataUrl}
                            alt={`${previewSoftwareName} logo preview`}
                            className="w-full h-full object-contain"
                          />
                        ) : (
                          <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-blue-600 via-indigo-600 to-cyan-500 flex items-center justify-center text-white shadow-xs">
                            <BatteryCharging className="w-6 h-6" />
                          </div>
                        )}
                      </div>

                      <div className="text-[11px] text-slate-500 dark:text-slate-400">
                        {selectedFileName ? (
                          <span className="font-medium text-blue-600 dark:text-blue-400 break-all">
                            {selectedFileName}
                          </span>
                        ) : draftLogoDataUrl ? (
                          <span>Custom uploaded logo active</span>
                        ) : (
                          <span>Default ERP icon active</span>
                        )}
                      </div>

                      {(draftLogoDataUrl || branding.logoDataUrl) && canEditBranding && (
                        <button
                          type="button"
                          onClick={handleResetLogoToDefault}
                          disabled={isSaving}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-rose-50 dark:hover:bg-rose-950/40 text-slate-600 dark:text-slate-300 hover:text-rose-600 dark:hover:text-rose-400 text-[11px] font-semibold transition-colors cursor-pointer"
                        >
                          <Trash2 className="w-3 h-3" />
                          <span>Reset to Default Icon</span>
                        </button>
                      )}
                    </div>

                    {/* Upload / Replace Dropzone */}
                    <div
                      onDragOver={(e) => {
                        e.preventDefault();
                        if (canEditBranding) setIsDragging(true);
                      }}
                      onDragLeave={(e) => {
                        e.preventDefault();
                        setIsDragging(false);
                      }}
                      onDrop={handleDrop}
                      className={`md:col-span-8 rounded-2xl border-2 border-dashed p-5 flex flex-col items-center justify-center text-center gap-3 transition-all ${
                        isDragging
                          ? 'border-blue-500 bg-blue-50/70 dark:bg-blue-950/30'
                          : 'border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900/60 hover:border-blue-400 dark:hover:border-blue-600'
                      } ${!canEditBranding ? 'opacity-60 pointer-events-none' : ''}`}
                    >
                      <input
                        ref={fileInputRef}
                        type="file"
                        accept="image/png,image/jpeg,image/webp,image/svg+xml,image/gif,image/x-icon,.png,.jpg,.jpeg,.webp,.svg,.gif,.ico"
                        onChange={handleFileInputChange}
                        className="hidden"
                        aria-label="Upload Software Logo"
                      />
                      <div className="w-11 h-11 rounded-2xl bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                        <ImagePlus className="w-5 h-5" />
                      </div>
                      <div className="space-y-1">
                        <p className="text-xs font-bold text-slate-800 dark:text-slate-100">
                          {draftLogoDataUrl
                            ? 'Replace Existing Software Logo'
                            : 'Upload New Software Logo or Icon'}
                        </p>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400">
                          Drag and drop an image here, or browse from your computer. Supports PNG, JPG, WEBP, SVG, GIF, or ICO (max 1.5 MB).
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => fileInputRef.current?.click()}
                        disabled={!canEditBranding || isSaving}
                        className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900 dark:bg-slate-700 hover:bg-slate-800 dark:hover:bg-slate-600 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer disabled:opacity-60"
                      >
                        <Upload className="w-3.5 h-3.5" />
                        <span>{draftLogoDataUrl ? 'Replace Logo' : 'Choose Logo File'}</span>
                      </button>
                    </div>
                  </div>
                </div>

                <hr className="border-slate-200 dark:border-slate-800" />

                {/* Live Global Preview */}
                <div className="space-y-2.5">
                  <div className="flex items-center gap-1.5 text-xs font-bold text-slate-800 dark:text-slate-200">
                    <Sparkles className="w-3.5 h-3.5 text-indigo-500" />
                    <span>Live Global Preview</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Sidebar Brand Preview */}
                    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 p-3.5 space-y-2">
                      <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                        Sidebar Header Preview
                      </div>
                      <div className="flex items-center gap-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl px-3 py-2.5">
                        {draftLogoDataUrl ? (
                          <img
                            src={draftLogoDataUrl}
                            alt="Sidebar logo preview"
                            className="w-8 h-8 rounded-xl object-contain bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 p-0.5 shrink-0"
                          />
                        ) : (
                          <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-blue-600 via-indigo-600 to-cyan-500 flex items-center justify-center text-white shadow-xs shrink-0">
                            <BatteryCharging className="w-4 h-4" />
                          </div>
                        )}
                        <div className="min-w-0">
                          <div className="flex items-center gap-1">
                            <span className="font-black text-sm tracking-tight bg-gradient-to-r from-blue-600 to-indigo-600 dark:from-blue-400 dark:to-indigo-400 bg-clip-text text-transparent truncate">
                              {isDefaultEnsecName ? 'ENSEC' : previewSoftwareName}
                            </span>
                            {isDefaultEnsecName && (
                              <span className="text-[9px] uppercase font-bold tracking-wider px-1 py-0.2 rounded bg-blue-100 dark:bg-blue-950/70 text-blue-700 dark:text-blue-300">
                                ERP
                              </span>
                            )}
                          </div>
                          <p className="text-[9px] text-slate-500 dark:text-slate-400 leading-none truncate">
                            {isDefaultEnsecName ? 'Lithium Battery BD' : 'Enterprise Resource Planning'}
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Login Page Header Preview */}
                    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 p-3.5 space-y-2">
                      <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                        Login Page Preview
                      </div>
                      <div className="flex items-center gap-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl px-3.5 py-2.5">
                        {draftLogoDataUrl ? (
                          <img
                            src={draftLogoDataUrl}
                            alt="Login logo preview"
                            className="w-9 h-9 rounded-xl object-contain bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 p-0.5 shrink-0"
                          />
                        ) : (
                          <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-indigo-600 via-blue-600 to-cyan-500 flex items-center justify-center text-white shadow-xs shrink-0">
                            <BatteryCharging className="w-4.5 h-4.5" />
                          </div>
                        )}
                        <div className="min-w-0">
                          <div className="text-xs font-extrabold text-slate-900 dark:text-white truncate">
                            Welcome to {previewSoftwareName}
                          </div>
                          <div className="text-[10px] text-slate-500 dark:text-slate-400 truncate">
                            {previewSoftwareName} • Enterprise RBAC Protected
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Form Footer Actions */}
              {canEditBranding && (
                <div className="px-6 py-4 bg-slate-50/80 dark:bg-slate-800/40 border-t border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-3">
                  <div className="text-[11px] text-slate-500 dark:text-slate-400">
                    {hasUnsavedChanges
                      ? 'You have unsaved System Branding changes.'
                      : 'All System Branding changes are saved and active globally.'}
                  </div>
                  <div className="flex items-center gap-2.5">
                    {hasUnsavedChanges && (
                      <button
                        type="button"
                        onClick={handleDiscardDraft}
                        disabled={isSaving}
                        className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold transition-colors cursor-pointer disabled:opacity-60"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        <span>Discard</span>
                      </button>
                    )}
                    <button
                      type="submit"
                      disabled={isSaving || !trimmedSoftwareName}
                      className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs font-bold shadow-sm hover:shadow transition-all cursor-pointer disabled:opacity-60"
                    >
                      {isSaving ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                          <span>Saving Changes...</span>
                        </>
                      ) : (
                        <>
                          <Save className="w-3.5 h-3.5" />
                          <span>Save Changes</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              )}
            </form>
          )}
        </section>
      </div>
    </div>
  );
};
