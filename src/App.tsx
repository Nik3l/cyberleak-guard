import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  KeyRound, 
  Mail, 
  Layers, 
  Database, 
  Activity, 
  CheckCircle2, 
  AlertTriangle, 
  Copy, 
  Check, 
  RefreshCw, 
  RotateCw,
  Search, 
  Lock, 
  Eye, 
  EyeOff, 
  Info, 
  Flame, 
  Globe2, 
  ListChecks,
  AlertCircle,
  Download,
  ChevronDown,
  ChevronUp,
  Cpu,
  X,
  ExternalLink
} from 'lucide-react';
import { KNOWN_BREACHES, CURRENT_STATS, DataBreach } from './data/breaches.ts';
import { checkPasswordPwned, generateSecurePassword, PasswordCheckResult } from './utils/crypto.ts';

type ActiveTab = 'scanner' | 'generator' | 'breaches' | 'threats' | 'remediation';
type ScanMode = 'combo' | 'email' | 'password';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('scanner');
  const [scanMode, setScanMode] = useState<ScanMode>('combo');
  const [disclaimerExpanded, setDisclaimerExpanded] = useState(false);
  const [hasAudited, setHasAudited] = useState(false);
  const resultsRef = useRef<HTMLDivElement>(null);

  // Input states
  const [emailInput, setEmailInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<string>('');
  const [scanError, setScanError] = useState<string | null>(null);

  // Results
  const [passwordResult, setPasswordResult] = useState<PasswordCheckResult | null>(null);
  const [emailResult, setEmailResult] = useState<{
    email: string;
    breached: boolean;
    breachCount: number;
    passwordsLeakedCount?: number;
    pasteCount?: number;
    breaches: DataBreach[];
    riskLevel: string;
  } | null>(null);
  const [comboResult, setComboResult] = useState<{
    email: string;
    credentialStuffingRisk: 'Critical' | 'High' | 'Medium' | 'Low';
    securityScore: number;
    riskFactors: string[];
    positiveFactors: string[];
    isComboExposed: boolean;
  } | null>(null);

  // Derived audit status for dynamic RED / GREEN card & input borders
  const emailHasBreach = Boolean(emailResult?.breached);
  const passwordHasBreach = Boolean(passwordResult?.pwned);
  const comboHasBreach = Boolean(comboResult && comboResult.credentialStuffingRisk !== 'Low');

  const hasVulnerabilities = hasAudited && (
    (scanMode === 'email' && emailHasBreach) ||
    (scanMode === 'password' && passwordHasBreach) ||
    (scanMode === 'combo' && (emailHasBreach || passwordHasBreach || comboHasBreach)) ||
    (emailHasBreach || passwordHasBreach)
  );

  const isCompletelyClean = hasAudited && !hasVulnerabilities && (
    (emailResult !== null || passwordResult !== null) &&
    (!emailResult || !emailResult.breached) &&
    (!passwordResult || !passwordResult.pwned)
  );

  // Generator states
  const [genLength, setGenLength] = useState(20);
  const [genUpper, setGenUpper] = useState(true);
  const [genNumbers, setGenNumbers] = useState(true);
  const [genSymbols, setGenSymbols] = useState(true);
  const [generatedPassword, setGeneratedPassword] = useState('');
  const [genPwnedCheck, setGenPwnedCheck] = useState<boolean | null>(null);
  const [copied, setCopied] = useState(false);

  // Breach database filters
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');

  // Remediation checklist
  const [checklist, setChecklist] = useState<Record<string, boolean>>(() => {
    try {
      const saved = localStorage.getItem('cyberleak_checklist');
      return saved ? JSON.parse(saved) : {};
    } catch {
      return {};
    }
  });

  const toggleChecklist = (id: string) => {
    setChecklist(prev => {
      const next = { ...prev, [id]: !prev[id] };
      localStorage.setItem('cyberleak_checklist', JSON.stringify(next));
      return next;
    });
  };

  // Generate initial password for generator
  useEffect(() => {
    generateNewPassword();
  }, [genLength, genUpper, genNumbers, genSymbols]);

  const generateNewPassword = async () => {
    const pw = generateSecurePassword(genLength, genSymbols, genNumbers, genUpper);
    setGeneratedPassword(pw);
    const check = await checkPasswordPwned(pw);
    setGenPwnedCheck(check.pwned);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const exportReport = () => {
    const reportData = {
      title: "Rapport d'Audit de Sécurité - CyberLeak Guard",
      generatedAt: new Date().toISOString(),
      auditor: "CyberLeak Guard (Bertrand CHAZAL - DSI 2026)",
      scanMode,
      targetEmail: emailResult?.email || (scanMode !== 'password' ? emailInput : undefined),
      comboAnalysis: comboResult ? {
        credentialStuffingRisk: comboResult.credentialStuffingRisk,
        securityScore: comboResult.securityScore,
        riskFactors: comboResult.riskFactors,
        positiveFactors: comboResult.positiveFactors
      } : undefined,
      emailExposure: emailResult ? {
        breached: emailResult.breached,
        breachCount: emailResult.breachCount,
        passwordsExposedInBreaches: emailResult.passwordsLeakedCount,
        breachesList: emailResult.breaches.map(b => ({
          name: b.name,
          date: b.breachDate,
          domain: b.domain,
          dataClasses: b.dataClasses
        }))
      } : undefined,
      passwordAnalysis: passwordResult ? {
        pwned: passwordResult.pwned,
        occurrencesInBreaches: passwordResult.count,
        entropyBits: passwordResult.entropy,
        strengthScore: `${passwordResult.strengthScore}/4`
      } : undefined
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyberleak-audit-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleModeSwitch = (mode: ScanMode) => {
    setScanMode(mode);
    setScanError(null);
    setPasswordResult(null);
    setEmailResult(null);
    setComboResult(null);
    setHasAudited(false);
  };

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setIsScanning(true);
    setScanError(null);
    setPasswordResult(null);
    setEmailResult(null);
    setComboResult(null);

    const hasEmail = Boolean(emailInput && emailInput.trim());
    const hasPassword = Boolean(passwordInput);

    // If both are empty, prompt user
    if (!hasEmail && !hasPassword) {
      setScanError('Veuillez saisir une adresse e-mail ou un mot de passe à analyser.');
      setIsScanning(false);
      return;
    }

    // Determine what to scan based on mode and filled fields
    const shouldScanPassword = scanMode === 'password' || (scanMode === 'combo' && hasPassword);
    const shouldScanEmail = scanMode === 'email' || (scanMode === 'combo' && hasEmail);

    try {
      let pwRes: PasswordCheckResult | null = null;
      let emResData: any = null;

      // 1. Password scan if requested or filled
      if (shouldScanPassword) {
        if (!passwordInput) {
          setScanError('Veuillez saisir un mot de passe à analyser.');
          setIsScanning(false);
          return;
        }
        setScanStatus('Calcul du hash SHA-1 et vérification k-anonymat...');
        try {
          pwRes = await checkPasswordPwned(passwordInput);
          setPasswordResult(pwRes);
        } catch (pwErr) {
          console.error('Password audit error:', pwErr);
        }
      }

      // 2. Email scan if requested or filled
      if (shouldScanEmail) {
        const cleanEmail = emailInput.trim();
        if (!cleanEmail || !cleanEmail.includes('@')) {
          setScanError('Veuillez saisir une adresse e-mail valide (ex: nom@domaine.fr).');
          setIsScanning(false);
          return;
        }
        setScanStatus('Interrogation de la base mondiale des fuites de données...');
        
        try {
          let res = await fetch('/api/check/email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: cleanEmail })
          });

          // Auto-retry once if transient network hitch occurs
          if (!res.ok) {
            await new Promise(r => setTimeout(r, 600));
            res = await fetch('/api/check/email', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ email: cleanEmail })
            });
          }

          if (res.ok) {
            emResData = await res.json();
            setEmailResult(emResData);
          } else {
            const errData = await res.json().catch(() => null);
            const errorMsg = errData?.error || "Le service d'audit n'a pas pu compléter l'analyse pour le moment. Veuillez relancer la vérification.";
            setScanError(errorMsg);
            setIsScanning(false);
            return;
          }
        } catch (fetchErr: any) {
          console.warn('Network error checking email:', fetchErr);
          setScanError("Impossible de joindre le serveur d'audit. Veuillez vérifier votre connexion et relancer le test.");
          setIsScanning(false);
          return;
        }
      }

      // 3. Combo evaluation (if both were analyzed)
      if (hasEmail && hasPassword && pwRes && emResData) {
        setScanStatus('Analyse de corrélation et risque de credential-stuffing...');
        try {
          const comboRes = await fetch('/api/check/combo', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              email: emailInput.trim(),
              passwordPwned: pwRes.pwned,
              passwordPwnedCount: pwRes.count,
              passwordLength: passwordInput.length,
              emailBreached: emResData.breached,
              emailBreachCount: emResData.breachCount,
              passwordsLeakedCount: emResData.passwordsLeakedCount
            })
          });

          if (comboRes.ok) {
            const comboData = await comboRes.json();
            setComboResult(comboData);
          }
        } catch (comboErr) {
          console.warn('Combo API error:', comboErr);
        }
      }

      // Mark audit as completed if at least one check succeeded
      if (pwRes || emResData) {
        setHasAudited(true);
        setTimeout(() => {
          resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 120);
      }
    } catch (err: any) {
      console.error('Scan error:', err);
      setScanError(err.message || 'Une erreur inattendue est survenue lors de l\'analyse.');
    } finally {
      setIsScanning(false);
      setScanStatus('');
    }
  };

  const loadExample = (type: 'compromised' | 'secure') => {
    setScanError(null);
    setHasAudited(false);
    setPasswordResult(null);
    setEmailResult(null);
    setComboResult(null);
    if (type === 'compromised') {
      setEmailInput('alex.martin@gmail.com');
      setPasswordInput('password123');
    } else {
      setEmailInput('mon.compte.securise.2026@proton.me');
      setPasswordInput('X9#vK2$mP8!zL4@qR7');
    }
  };

  const filteredBreaches = KNOWN_BREACHES.filter(b => {
    const matchesSearch = b.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      b.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      b.dataClasses.some(c => c.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesCat = categoryFilter === 'ALL' || b.category === categoryFilter;
    return matchesSearch && matchesCat;
  });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 cyber-grid flex flex-col selection:bg-emerald-500/30 selection:text-emerald-300">
      {/* Top Header - Desktop & Mobile */}
      <header className="border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-3 sm:px-4 lg:px-8 h-14 sm:h-16 flex items-center justify-between gap-1.5 sm:gap-3">
          <div className="flex items-center space-x-1.5 sm:space-x-2.5 lg:space-x-3 cursor-pointer shrink-0" onClick={() => setActiveTab('scanner')}>
            <div className="bg-white/95 hover:bg-white transition-all px-1.5 sm:px-2 py-1 rounded-xl shadow-sm border border-slate-700/60 flex items-center shrink-0">
              <img
                src="/assets/aistudio/LOGO-GSO-FONCE_365c143b.png"
                alt="Groupe Sud Ouest"
                className="h-5 sm:h-6 lg:h-7 w-auto object-contain"
              />
            </div>
            <div className="w-7 h-7 sm:w-8 sm:h-8 lg:w-9 lg:h-9 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 cyber-glow-emerald shrink-0">
              <Shield className="w-3.5 h-3.5 sm:w-4 sm:h-4 lg:w-4.5 lg:h-4.5" />
            </div>
            <div className="whitespace-nowrap">
              <span className="text-sm sm:text-base lg:text-lg xl:text-xl font-extrabold tracking-tight bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400 bg-clip-text text-transparent">
                CyberLeak Guard
              </span>
            </div>
          </div>

          {/* Desktop & Tablet Navigation Links */}
          <nav className="hidden md:flex items-center space-x-0.5 lg:space-x-1.5 xl:space-x-2 shrink-0">
            <button
              onClick={() => setActiveTab('scanner')}
              className={`px-1.5 py-1 lg:px-3 lg:py-1.5 rounded-lg text-[11px] lg:text-sm font-medium transition-colors flex items-center space-x-1 lg:space-x-1.5 shrink-0 ${
                activeTab === 'scanner'
                  ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Search className="w-3.5 h-3.5 lg:w-4 lg:h-4" />
              <span>Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('generator')}
              className={`px-1.5 py-1 lg:px-3 lg:py-1.5 rounded-lg text-[11px] lg:text-sm font-medium transition-colors flex items-center space-x-1 lg:space-x-1.5 shrink-0 ${
                activeTab === 'generator'
                  ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <KeyRound className="w-3.5 h-3.5 lg:w-4 lg:h-4" />
              <span>Générateur</span>
            </button>

            <button
              onClick={() => setActiveTab('breaches')}
              className={`px-1.5 py-1 lg:px-3 lg:py-1.5 rounded-lg text-[11px] lg:text-sm font-medium transition-colors flex items-center space-x-1 lg:space-x-1.5 shrink-0 ${
                activeTab === 'breaches'
                  ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Database className="w-3.5 h-3.5 lg:w-4 lg:h-4" />
              <span>Fuites</span>
            </button>

            <button
              onClick={() => setActiveTab('threats')}
              className={`px-1.5 py-1 lg:px-3 lg:py-1.5 rounded-lg text-[11px] lg:text-sm font-medium transition-colors flex items-center space-x-1 lg:space-x-1.5 shrink-0 ${
                activeTab === 'threats'
                  ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Activity className="w-3.5 h-3.5 lg:w-4 lg:h-4" />
              <span>Menaces</span>
            </button>

            <button
              onClick={() => setActiveTab('remediation')}
              className={`px-1.5 py-1 lg:px-3 lg:py-1.5 rounded-lg text-[11px] lg:text-sm font-medium transition-colors flex items-center space-x-1 lg:space-x-1.5 shrink-0 ${
                activeTab === 'remediation'
                  ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <ListChecks className="w-3.5 h-3.5 lg:w-4 lg:h-4" />
              <span>Plan<span className="hidden lg:inline"> d'action</span></span>
            </button>
          </nav>

          {/* Status pill */}
          <div className="flex items-center shrink-0">
            <div className="flex items-center space-x-1 text-[10px] sm:text-[11px] font-mono px-2 sm:px-2.5 py-1 rounded-full bg-emerald-950/60 text-emerald-400 border border-emerald-800/60 whitespace-nowrap">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>K-Anonymat</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-3 sm:px-6 lg:px-8 py-5 sm:py-8">
        
        {/* TAB 1: SCANNER */}
        {activeTab === 'scanner' && (
          <div className="space-y-6 sm:space-y-8">
            {/* Hero Banner */}
            <div className="text-center max-w-3xl mx-auto space-y-3 sm:space-y-4">
              <div className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-[11px] sm:text-xs font-mono text-emerald-400">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span>Base mondiale en direct • +14,9 Md analysés</span>
              </div>
              <h1 className="text-2xl sm:text-4xl md:text-5xl font-extrabold tracking-tight text-white leading-tight">
                Vérifiez si vos identifiants ont été{' '}
                <span className="bg-gradient-to-r from-red-400 via-rose-400 to-amber-400 bg-clip-text text-transparent">
                  divulgués en ligne
                </span>
              </h1>
              <p className="text-slate-400 text-xs sm:text-base max-w-2xl mx-auto leading-relaxed">
                Recherchez si votre adresse e-mail, votre mot de passe ou votre combo (les deux ensemble) figurent dans des violations de données ou des logs de cyberattaques.
              </p>

              {/* Mode Selectors - Responsive Grid for mobile and desktop */}
              <div className="grid grid-cols-3 gap-1 p-1 rounded-xl bg-slate-900/90 border border-slate-800 max-w-md mx-auto text-xs sm:text-sm">
                <button
                  type="button"
                  onClick={() => handleModeSwitch('combo')}
                  className={`py-2 px-1 sm:px-3 rounded-lg font-medium transition-all flex flex-col sm:flex-row items-center justify-center space-y-0.5 sm:space-y-0 sm:space-x-1.5 ${
                    scanMode === 'combo'
                      ? 'bg-emerald-500 text-slate-950 shadow-md font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Layers className="w-3.5 h-3.5 sm:w-4 sm:h-4 shrink-0" />
                  <span className="truncate">Combo</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleModeSwitch('email')}
                  className={`py-2 px-1 sm:px-3 rounded-lg font-medium transition-all flex flex-col sm:flex-row items-center justify-center space-y-0.5 sm:space-y-0 sm:space-x-1.5 ${
                    scanMode === 'email'
                      ? 'bg-emerald-500 text-slate-950 shadow-md font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Mail className="w-3.5 h-3.5 sm:w-4 sm:h-4 shrink-0" />
                  <span className="truncate">E-mail</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleModeSwitch('password')}
                  className={`py-2 px-1 sm:px-3 rounded-lg font-medium transition-all flex flex-col sm:flex-row items-center justify-center space-y-0.5 sm:space-y-0 sm:space-x-1.5 ${
                    scanMode === 'password'
                      ? 'bg-emerald-500 text-slate-950 shadow-md font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <KeyRound className="w-3.5 h-3.5 sm:w-4 sm:h-4 shrink-0" />
                  <span className="truncate">Mot de passe</span>
                </button>
              </div>
            </div>

            {/* Input Form Box - Dynamically changes to RED (breaches/vulnerabilities found) or GREEN (totally clean/safe) */}
            <div className={`max-w-3xl mx-auto rounded-2xl p-4 sm:p-8 backdrop-blur-sm space-y-5 transition-all duration-300 ${
              hasVulnerabilities
                ? 'border-2 border-red-500 shadow-2xl shadow-red-500/25 bg-gradient-to-b from-red-950/40 via-slate-900/95 to-slate-900 ring-2 ring-red-500/30'
                : isCompletelyClean
                ? 'border-2 border-emerald-500 shadow-2xl shadow-emerald-500/25 bg-gradient-to-b from-emerald-950/40 via-slate-900/95 to-slate-900 ring-2 ring-emerald-500/30'
                : 'bg-slate-900/80 border border-slate-800 shadow-xl'
            }`}>
              {/* Dynamic Status Banner inside the card */}
              {hasVulnerabilities && (
                <div className="p-3 sm:p-3.5 rounded-xl bg-red-950/80 border border-red-500/70 text-red-200 flex items-center justify-between gap-3 shadow-md shadow-red-500/10 animate-in fade-in">
                  <div className="flex items-center space-x-2.5">
                    <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
                    <div>
                      <span className="font-bold text-white text-xs sm:text-sm block">
                        ATTENTION : Faille(s) de sécurité détectée(s)
                      </span>
                      <span className="text-[11px] text-red-300">
                        Un ou plusieurs éléments testés apparaissent dans des violations de données publiques.
                      </span>
                    </div>
                  </div>
                  <span className="px-2.5 py-1 rounded bg-red-600 text-white font-mono text-[11px] font-bold tracking-wider shrink-0 uppercase">
                    Compromis
                  </span>
                </div>
              )}

              {isCompletelyClean && (
                <div className="p-3 sm:p-3.5 rounded-xl bg-emerald-950/80 border border-emerald-500/70 text-emerald-200 flex items-center justify-between gap-3 shadow-md shadow-emerald-500/10 animate-in fade-in">
                  <div className="flex items-center space-x-2.5">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                    <div>
                      <span className="font-bold text-white text-xs sm:text-sm block">
                        SÉCURISÉ : Aucune faille de sécurité détectée
                      </span>
                      <span className="text-[11px] text-emerald-300">
                        Les éléments analysés ne figurent dans aucune des brèches de données mondiales répertoriées.
                      </span>
                    </div>
                  </div>
                  <span className="px-2.5 py-1 rounded bg-emerald-500 text-slate-950 font-mono text-[11px] font-bold tracking-wider shrink-0 uppercase">
                    Protégé
                  </span>
                </div>
              )}

              <form onSubmit={handleScan} className="space-y-4">
                {(scanMode === 'email' || scanMode === 'combo') && (
                  <div>
                    <label className="block text-xs sm:text-sm font-medium text-slate-300 mb-1.5 flex items-center justify-between">
                      <span className="flex items-center space-x-1.5">
                        <Mail className={`w-4 h-4 ${
                          emailResult?.breached ? 'text-red-400' : (emailResult && !emailResult.breached) ? 'text-emerald-400' : 'text-emerald-400'
                        }`} />
                        <span>Adresse e-mail à vérifier</span>
                      </span>
                      <span className="text-[11px] text-slate-500 hidden sm:inline">Ex: b.chazal@sudouest.fr</span>
                    </label>
                    <div className="relative flex items-center">
                      <input
                        type="email"
                        value={emailInput}
                        onChange={(e) => {
                          setEmailInput(e.target.value);
                          if (emailResult) {
                            setEmailResult(null);
                            setComboResult(null);
                            setHasAudited(false);
                          }
                        }}
                        placeholder="prenom.nom@domaine.fr"
                        required={scanMode === 'email'}
                        autoComplete="off"
                        autoCorrect="off"
                        spellCheck={false}
                        maxLength={254}
                        className={`w-full rounded-xl px-3.5 py-3 text-base font-mono transition-all duration-200 ${
                          emailResult?.breached
                            ? 'bg-red-950/40 border-2 border-red-500 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-400 shadow-lg shadow-red-500/20'
                            : (emailResult && !emailResult.breached)
                            ? 'bg-emerald-950/30 border-2 border-emerald-500 text-emerald-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-400 shadow-lg shadow-emerald-500/20'
                            : 'bg-slate-950 border border-slate-700/80 text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent'
                        } ${emailInput ? 'pr-11' : ''}`}
                      />
                      {emailInput.length > 0 && (
                        <button
                          type="button"
                          onClick={() => {
                            setEmailInput('');
                            setEmailResult(null);
                            setComboResult(null);
                            setHasAudited(false);
                          }}
                          className="absolute right-2.5 top-1/2 -translate-y-1/2 w-8 h-8 flex items-center justify-center rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors cursor-pointer"
                          title="Effacer l'adresse e-mail"
                          aria-label="Effacer l'adresse e-mail"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                    {emailResult && (
                      <div className={`mt-2 flex items-center space-x-1.5 text-xs font-medium animate-in fade-in ${
                        emailResult.breached ? 'text-red-400' : 'text-emerald-400'
                      }`}>
                        {emailResult.breached ? (
                          <>
                            <AlertCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                            <span>
                              Adresse compromise dans {emailResult.breachCount} fuite{emailResult.breachCount > 1 ? 's' : ''} de données{emailResult.passwordsLeakedCount ? ` (dont ${emailResult.passwordsLeakedCount} fuite${emailResult.passwordsLeakedCount > 1 ? 's' : ''} avec mots de passe exposés)` : ''}.
                            </span>
                          </>
                        ) : (
                          <>
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                            <span>Adresse sécurisée : aucune fuite de données répertoriée pour cet e-mail.</span>
                          </>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {(scanMode === 'password' || scanMode === 'combo') && (
                  <div>
                    <label className="block text-xs sm:text-sm font-medium text-slate-300 mb-1.5 flex items-center justify-between">
                      <span className="flex items-center space-x-1.5">
                        <KeyRound className={`w-4 h-4 ${
                          passwordResult?.pwned ? 'text-red-400' : (passwordResult && !passwordResult.pwned) ? 'text-emerald-400' : 'text-emerald-400'
                        }`} />
                        <span>Mot de passe à vérifier</span>
                      </span>
                      <span className="text-[11px] text-emerald-400 font-mono flex items-center space-x-1">
                        <Lock className="w-3 h-3" />
                        <span>K-Anonymat SHA-1</span>
                      </span>
                    </label>
                    <div className="relative flex items-center">
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={passwordInput}
                        onChange={(e) => {
                          setPasswordInput(e.target.value);
                          if (passwordResult) {
                            setPasswordResult(null);
                            setComboResult(null);
                            setHasAudited(false);
                          }
                        }}
                        placeholder="Saisissez un mot de passe à tester"
                        required={scanMode === 'password'}
                        autoComplete="new-password"
                        autoCorrect="off"
                        spellCheck={false}
                        maxLength={512}
                        className={`w-full rounded-xl px-3.5 py-3 text-base font-mono pr-20 transition-all duration-200 ${
                          passwordResult?.pwned
                            ? 'bg-red-950/40 border-2 border-red-500 text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-red-400 shadow-lg shadow-red-500/20'
                            : (passwordResult && !passwordResult.pwned)
                            ? 'bg-emerald-950/30 border-2 border-emerald-500 text-emerald-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-400 shadow-lg shadow-emerald-500/20'
                            : 'bg-slate-950 border border-slate-700/80 text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent'
                        }`}
                      />
                      <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center space-x-1">
                        {passwordInput.length > 0 && (
                          <button
                            type="button"
                            onClick={() => {
                              setPasswordInput('');
                              setPasswordResult(null);
                              setComboResult(null);
                              setHasAudited(false);
                            }}
                            className="w-8 h-8 flex items-center justify-center rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors cursor-pointer"
                            title="Effacer le mot de passe"
                            aria-label="Effacer le mot de passe"
                          >
                            <X className="w-4 h-4" />
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => setShowPassword(!showPassword)}
                          className="w-8 h-8 flex items-center justify-center rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 transition-colors cursor-pointer"
                          title={showPassword ? "Masquer" : "Afficher"}
                          aria-label={showPassword ? "Masquer le mot de passe" : "Afficher le mot de passe"}
                        >
                          {showPassword ? <EyeOff className="w-4 h-4 sm:w-5 sm:h-5" /> : <Eye className="w-4 h-4 sm:w-5 sm:h-5" />}
                        </button>
                      </div>
                    </div>
                    {passwordResult && (
                      <div className={`mt-2 flex items-center space-x-1.5 text-xs font-medium animate-in fade-in ${
                        passwordResult.pwned ? 'text-red-400' : 'text-emerald-400'
                      }`}>
                        {passwordResult.pwned ? (
                          <>
                            <AlertCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                            <span>
                              Mot de passe compromis : découvert {passwordResult.count.toLocaleString()} fois dans les registres criminels.
                            </span>
                          </>
                        ) : (
                          <>
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                            <span>Mot de passe sain : jamais apparu dans les violations de données répertoriées.</span>
                          </>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {scanError && (
                  <div className="p-3.5 rounded-xl bg-rose-950/60 border border-rose-700/80 text-xs sm:text-sm text-rose-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 animate-in fade-in">
                    <div className="flex items-start space-x-2.5">
                      <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5 sm:mt-0" />
                      <div className="space-y-0.5">
                        <span className="font-semibold text-white block">Alerte sécurité / Vérification :</span>
                        <p className="text-rose-200 leading-relaxed text-xs">{scanError}</p>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleScan()}
                      className="self-end sm:self-auto px-3 py-1.5 rounded-lg bg-rose-900/80 hover:bg-rose-800 text-white font-semibold text-xs border border-rose-600 transition-colors cursor-pointer shrink-0"
                    >
                      Réessayer
                    </button>
                  </div>
                )}

                <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-1">
                  <div className="flex items-center space-x-1.5 text-xs text-slate-400">
                    <span className="text-[11px]">Exemples :</span>
                    <button
                      type="button"
                      onClick={() => loadExample('compromised')}
                      className="px-2.5 py-1 rounded bg-rose-950/40 text-rose-300 hover:bg-rose-900/50 border border-rose-800/50 transition-colors text-[11px]"
                    >
                      Compromis
                    </button>
                    <button
                      type="button"
                      onClick={() => loadExample('secure')}
                      className="px-2.5 py-1 rounded bg-emerald-950/40 text-emerald-300 hover:bg-emerald-900/50 border border-emerald-800/50 transition-colors text-[11px]"
                    >
                      Sécurisé
                    </button>
                  </div>

                  <button
                    type="submit"
                    disabled={isScanning || (!emailInput && !passwordInput) || (scanMode === 'email' && !emailInput) || (scanMode === 'password' && !passwordInput)}
                    className="w-full sm:w-auto px-6 py-3 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-slate-950 font-bold text-sm sm:text-base flex items-center justify-center space-x-2 shadow-lg hover:shadow-emerald-500/25 transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
                  >
                    {isScanning ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin shrink-0" />
                        <span className="truncate">{scanStatus || 'Analyse en cours...'}</span>
                      </>
                    ) : (
                      <>
                        {hasAudited ? (
                          <RotateCw className="w-4 h-4 shrink-0" />
                        ) : (
                          <Shield className="w-4 h-4 shrink-0" />
                        )}
                        <span>
                          {scanMode === 'password' || (!emailInput && passwordInput)
                            ? `${hasAudited ? 'Relancer' : 'Lancer'} l'audit du mot de passe`
                            : scanMode === 'email' || (emailInput && !passwordInput)
                            ? `${hasAudited ? 'Relancer' : 'Lancer'} l'audit de l'e-mail`
                            : `${hasAudited ? 'Relancer' : 'Lancer'} l'audit de sécurité combiné`}
                        </span>
                      </>
                    )}
                  </button>
                </div>
              </form>
            </div>

            {/* RESULTS SECTION - Placé immédiatement sous la fenêtre de test, au-dessus du disclaimer */}
            {(passwordResult || emailResult || comboResult) && (
              <div ref={resultsRef} id="scan-results" className="max-w-4xl mx-auto space-y-5 animate-in fade-in duration-300 scroll-mt-20">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 border-b border-slate-800 pb-3">
                  <div className="flex items-center space-x-2">
                    <Activity className="w-4 h-4 sm:w-5 sm:h-5 text-emerald-400" />
                    <h2 className="text-base sm:text-xl font-bold text-white">
                      Rapport d'audit de sécurité ({scanMode.toUpperCase()})
                    </h2>
                  </div>
                  <div className="flex items-center justify-between sm:justify-end space-x-2.5">
                    <span className="text-[11px] font-mono text-slate-500">
                      {new Date().toLocaleTimeString()}
                    </span>
                    <button
                      type="button"
                      onClick={exportReport}
                      className="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-[11px] text-emerald-400 border border-emerald-800/50 flex items-center space-x-1.5 transition-colors cursor-pointer"
                      title="Télécharger l'audit au format JSON"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Exporter (JSON)</span>
                    </button>
                  </div>
                </div>

                {/* Combo Result Banner */}
                {comboResult && (
                  <div className={`p-4 sm:p-6 rounded-2xl border ${
                    comboResult.credentialStuffingRisk === 'Critical'
                      ? 'bg-rose-950/30 border-rose-600/50 cyber-glow-rose'
                      : comboResult.credentialStuffingRisk === 'High'
                      ? 'bg-amber-950/30 border-amber-600/50'
                      : comboResult.credentialStuffingRisk === 'Medium'
                      ? 'bg-blue-950/30 border-blue-600/50'
                      : 'bg-emerald-950/30 border-emerald-600/50 cyber-glow-emerald'
                  }`}>
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                      <div className="flex items-start space-x-3 sm:space-x-4">
                        {comboResult.credentialStuffingRisk === 'Critical' ? (
                          <ShieldAlert className="w-8 h-8 sm:w-12 sm:h-12 text-rose-400 shrink-0" />
                        ) : comboResult.credentialStuffingRisk === 'High' ? (
                          <AlertTriangle className="w-8 h-8 sm:w-12 sm:h-12 text-amber-400 shrink-0" />
                        ) : comboResult.credentialStuffingRisk === 'Medium' ? (
                          <Info className="w-8 h-8 sm:w-12 sm:h-12 text-cyan-400 shrink-0" />
                        ) : (
                          <ShieldCheck className="w-8 h-8 sm:w-12 sm:h-12 text-emerald-400 shrink-0" />
                        )}
                        <div>
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="text-[10px] sm:text-xs uppercase font-mono tracking-wider px-2 py-0.5 rounded font-bold bg-slate-900 border border-slate-700">
                              Bourrage d'Identifiants (Stuffing)
                            </span>
                            <span className={`text-[10px] sm:text-xs uppercase font-mono font-bold px-2 py-0.5 rounded ${
                              comboResult.credentialStuffingRisk === 'Critical'
                                ? 'bg-rose-500/20 text-rose-400'
                                : comboResult.credentialStuffingRisk === 'High'
                                ? 'bg-amber-500/20 text-amber-400'
                                : comboResult.credentialStuffingRisk === 'Medium'
                                ? 'bg-blue-500/20 text-blue-400'
                                : 'bg-emerald-500/20 text-emerald-400'
                            }`}>
                              Niveau {comboResult.credentialStuffingRisk}
                            </span>
                          </div>
                          <h3 className="text-base sm:text-xl font-bold text-white mt-1.5">
                            {comboResult.credentialStuffingRisk === 'Critical'
                              ? 'Alerte critique : Combo vulnérable aux attaques automatisées'
                              : comboResult.credentialStuffingRisk === 'High'
                              ? 'Attention : Mot de passe compromis dans des bases publiques'
                              : comboResult.credentialStuffingRisk === 'Medium'
                              ? 'Adresse e-mail dans des brèches, mais mot de passe sain'
                              : 'Sécurité optimale : Aucune fuite détectée'}
                          </h3>
                          <p className="text-xs sm:text-sm text-slate-300 mt-1 leading-relaxed">
                            {comboResult.credentialStuffingRisk === 'Critical'
                              ? 'Votre e-mail ET ce mot de passe sont tous deux répertoriés dans des fuites de données. Les cybercriminels automatisent des attaques de bourrage d\'identifiants avec ce type de combinaison.'
                              : comboResult.credentialStuffingRisk === 'Medium'
                              ? 'Votre adresse e-mail figure dans des brèches historiques, mais le mot de passe testé n\'a JAMAIS fuité. Si vous ne réutilisez pas d\'ancien mot de passe, vous êtes protégé.'
                              : 'Cette combinaison présente un très bon niveau de sécurité face aux listes de diffusion criminelles.'}
                          </p>
                        </div>
                      </div>

                      <div className="bg-slate-900/90 border border-slate-800 p-3 sm:p-4 rounded-xl text-center self-start sm:self-auto min-w-[120px] w-full sm:w-auto">
                        <span className="text-[10px] sm:text-xs text-slate-400 uppercase font-mono">Score de Sécurité</span>
                        <div className={`text-2xl sm:text-3xl font-extrabold mt-0.5 ${
                          comboResult.securityScore < 40 ? 'text-rose-400' : comboResult.securityScore < 70 ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {comboResult.securityScore}/100
                        </div>
                      </div>
                    </div>

                    {comboResult.riskFactors.length > 0 && (
                      <div className="mt-3.5 pt-3.5 border-t border-slate-800/80 space-y-1">
                        <span className="text-[10px] sm:text-xs font-semibold uppercase text-slate-400 tracking-wider">Facteurs de risque identifiés :</span>
                        {comboResult.riskFactors.map((factor, idx) => (
                          <div key={idx} className="flex items-start space-x-2 text-xs sm:text-sm text-rose-300">
                            <Flame className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-rose-400 shrink-0 mt-0.5" />
                            <span>{factor}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {comboResult.positiveFactors.length > 0 && (
                      <div className="mt-2.5 pt-2.5 border-t border-slate-800/80 space-y-1">
                        <span className="text-[10px] sm:text-xs font-semibold uppercase text-slate-400 tracking-wider">Points positifs :</span>
                        {comboResult.positiveFactors.map((point, idx) => (
                          <div key={idx} className="flex items-start space-x-2 text-xs sm:text-sm text-emerald-300">
                            <CheckCircle2 className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-emerald-400 shrink-0 mt-0.5" />
                            <span>{point}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Email Breaches Detail */}
                {emailResult && (
                  <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 sm:p-6 space-y-3.5">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 border-b border-slate-800 pb-2.5">
                      <div className="flex items-center space-x-2 text-slate-200 font-semibold text-sm sm:text-base">
                        <Mail className="w-4 h-4 text-emerald-400 shrink-0" />
                        <span className="truncate">Fuites réelles associées ({emailResult.breachCount})</span>
                      </div>
                      <span className={`text-[10px] sm:text-xs px-2 py-0.5 rounded-full font-bold uppercase font-mono w-fit ${
                        emailResult.breached ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {emailResult.breached ? `${emailResult.breachCount} Fuite(s) Détectée(s)` : '0 Fuite Détectée'}
                      </span>
                    </div>

                    {emailResult.breaches.length === 0 ? (
                      <div className="p-6 text-center bg-slate-950/60 rounded-xl border border-slate-800">
                        <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
                        <h4 className="text-sm sm:text-base font-bold text-white">Excellente nouvelle !</h4>
                        <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-md mx-auto">
                          Cette adresse e-mail ({emailResult.email}) n'a été trouvée dans aucune fuite publique majeure recensée.
                        </p>
                      </div>
                    ) : (
                      <div className="space-y-2.5">
                        <div className="p-2.5 bg-slate-950 rounded-xl border border-slate-800 text-[11px] sm:text-xs text-slate-300 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                          <span>Données indexées en direct depuis les registres de cyberattaques.</span>
                          {emailResult.passwordsLeakedCount !== undefined && emailResult.passwordsLeakedCount > 0 && (
                            <span className="text-rose-400 font-bold">
                              ⚠️ {emailResult.passwordsLeakedCount} fuite(s) avec mots de passe exposés
                            </span>
                          )}
                        </div>

                        {emailResult.breaches.map((breach, idx) => (
                          <div key={`${breach.id || breach.name}-${idx}`} className="p-3.5 sm:p-4 bg-slate-950 rounded-xl border border-slate-800/80 space-y-2.5">
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
                              <div>
                                <h4 className="text-sm sm:text-base font-bold text-white flex items-center space-x-2">
                                  <span>{breach.name}</span>
                                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 font-mono">
                                    {breach.breachDate}
                                  </span>
                                </h4>
                                {breach.domain && <span className="text-xs text-slate-400 font-mono">{breach.domain}</span>}
                              </div>
                              <span className={`text-[10px] sm:text-xs font-mono font-bold px-2 py-0.5 rounded w-fit ${
                                breach.severity === 'Critical'
                                  ? 'bg-rose-950 text-rose-300 border border-rose-800'
                                  : breach.severity === 'High'
                                  ? 'bg-amber-950 text-amber-300 border border-amber-800'
                                  : 'bg-blue-950 text-blue-300 border border-blue-800'
                              }`}>
                                {breach.severity} {breach.pwnCount ? `(${breach.pwnCount.toLocaleString()} comptes)` : ''}
                              </span>
                            </div>

                            <p className="text-xs text-slate-300 leading-relaxed">{breach.description}</p>

                            <div>
                              <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">Données compromises :</span>
                              <div className="flex flex-wrap gap-1">
                                {breach.dataClasses.map((dc, i) => (
                                  <span key={i} className={`text-[11px] px-2 py-0.5 rounded-md border ${
                                    dc.toLowerCase().includes('password') || dc.toLowerCase().includes('mot de passe')
                                      ? 'bg-rose-950/60 text-rose-300 border-rose-800 font-semibold'
                                      : 'bg-slate-900 text-slate-300 border-slate-800'
                                  }`}>
                                    {dc}
                                  </span>
                                ))}
                              </div>
                            </div>

                            <div className="p-2 sm:p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-900/30 text-[11px] sm:text-xs text-emerald-300 flex items-start space-x-2">
                              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                              <div>
                                <strong>Recommandation : </strong>{breach.remediationAdvice}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Cross-check with HaveIBeenPwned */}
                    <div className="p-3 sm:p-4 rounded-xl bg-slate-950/90 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div className="flex items-start space-x-3">
                        <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/30 flex items-center justify-center text-sky-400 shrink-0 mt-0.5">
                          <Globe2 className="w-4 h-4" />
                        </div>
                        <div>
                          <div className="text-xs sm:text-sm font-bold text-white flex flex-wrap items-center gap-1.5">
                            <span>Contre-vérification indépendante</span>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800">
                              Have I Been Pwned
                            </span>
                          </div>
                          <p className="text-[11px] sm:text-xs text-slate-400 mt-0.5">
                            Comparez et recoupez ce résultat directement sur le portail mondial de référence de Troy Hunt.
                          </p>
                        </div>
                      </div>
                      <a
                        href="https://haveibeenpwned.com/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="self-start sm:self-auto px-3.5 py-2 rounded-lg bg-sky-600/20 hover:bg-sky-600/30 text-sky-300 border border-sky-500/40 text-xs font-semibold flex items-center space-x-1.5 transition-colors shrink-0"
                      >
                        <span>Vérifier sur HaveIBeenPwned</span>
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    </div>
                  </div>
                )}

                {/* Password Analysis Detail */}
                {passwordResult && (
                  <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 sm:p-6 space-y-3.5">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 border-b border-slate-800 pb-2.5">
                      <div className="flex items-center space-x-2 text-slate-200 font-semibold text-sm sm:text-base">
                        <KeyRound className="w-4 h-4 text-emerald-400 shrink-0" />
                        <span>Analyse du Mot de Passe (K-Anonymat SHA-1)</span>
                      </div>
                      <span className={`text-[10px] sm:text-xs px-2 py-0.5 rounded-full font-bold uppercase font-mono w-fit ${
                        passwordResult.pwned ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {passwordResult.pwned ? `Compromis (${passwordResult.count.toLocaleString()} fois)` : 'Vierge de toute fuite'}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 sm:gap-4">
                      <div className="bg-slate-950 p-3 sm:p-4 rounded-xl border border-slate-800">
                        <span className="text-[11px] text-slate-400">Occurrences fuites</span>
                        <div className={`text-lg sm:text-2xl font-bold font-mono mt-0.5 ${passwordResult.count > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                          {passwordResult.count.toLocaleString()}
                        </div>
                      </div>

                      <div className="bg-slate-950 p-3 sm:p-4 rounded-xl border border-slate-800">
                        <span className="text-[11px] text-slate-400">Entropie estimée</span>
                        <div className="text-lg sm:text-2xl font-bold font-mono text-cyan-400 mt-0.5">
                          {passwordResult.entropy} bits
                        </div>
                      </div>

                      <div className="bg-slate-950 p-3 sm:p-4 rounded-xl border border-slate-800 col-span-2 sm:col-span-1">
                        <span className="text-[11px] text-slate-400">Niveau de solidité</span>
                        <div className="flex items-center space-x-1.5 mt-2">
                          {[0, 1, 2, 3].map((lvl) => (
                            <div
                              key={lvl}
                              className={`h-2.5 flex-1 rounded ${
                                lvl <= passwordResult.strengthScore - 1
                                  ? passwordResult.strengthScore <= 1
                                    ? 'bg-rose-500'
                                    : passwordResult.strengthScore <= 2
                                    ? 'bg-amber-500'
                                    : 'bg-emerald-500'
                                  : 'bg-slate-800'
                              }`}
                            />
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Hash Details */}
                    <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-[11px] sm:text-xs font-mono space-y-1 text-slate-400 break-all">
                      <div className="text-slate-300 font-semibold mb-1">Preuve k-anonymat :</div>
                      <div>Préfixe public : <span className="text-emerald-400 font-bold">{passwordResult.hashPrefix}</span></div>
                      <div>Suffixe privé en mémoire : <span className="text-slate-500">{passwordResult.hashSuffix}</span></div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Security, Encryption & K-Anonymity Disclaimer - Placé sous les résultats */}
            <div className="max-w-4xl mx-auto p-4 sm:p-5 rounded-2xl bg-slate-950/90 border border-emerald-500/30 space-y-4 text-xs shadow-lg">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 border-b border-slate-800 pb-3">
                <div className="flex items-start sm:items-center space-x-2.5">
                  <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0 mt-0.5 sm:mt-0">
                    <ShieldCheck className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-white flex flex-wrap items-center gap-1.5">
                      <span>Disclaimer de Confidentialité & Engagement Zéro Enregistrement</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-semibold">
                        Zéro Log Garanti
                      </span>
                    </h4>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      Vos adresses e-mails et mots de passe ne sont <strong>JAMAIS enregistrés</strong>, tracés ni conservés.
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => setDisclaimerExpanded(!disclaimerExpanded)}
                  className="self-start sm:self-auto text-[11px] text-emerald-400 hover:text-emerald-300 font-mono flex items-center space-x-1 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 transition-colors cursor-pointer shrink-0"
                >
                  <span>{disclaimerExpanded ? 'Masquer le schéma' : 'Comprendre le K-Anonymat'}</span>
                  {disclaimerExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                </button>
              </div>

              {/* 3 Pillars */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {/* Pillar 1: No-Log */}
                <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800/80 space-y-1.5">
                  <div className="flex items-center space-x-2 text-slate-200 font-semibold text-xs">
                    <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                    <span>1. Zéro Enregistrement (No-Log)</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Aucune base de données, aucun fichier journal (log) et aucun historique ne stocke vos données. Les calculs sont éphémères en mémoire vive : dès la fin du scan ou la fermeture du navigateur, tout est immédiatement effacé.
                  </p>
                </div>

                {/* Pillar 2: Encryption */}
                <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800/80 space-y-1.5">
                  <div className="flex items-center space-x-2 text-slate-200 font-semibold text-xs">
                    <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                    <span>2. Cryptage & Traitement Local</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Toutes les transmissions transitent sous canal sécurisé <strong>HTTPS / TLS 1.3</strong>. Le mot de passe est haché <em>localement dans votre navigateur</em> par l'API Web Crypto : <strong>votre mot de passe en clair ne transite jamais sur le réseau</strong>.
                  </p>
                </div>

                {/* Pillar 3: K-Anonymity */}
                <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800/80 space-y-1.5">
                  <div className="flex items-center space-x-2 text-slate-200 font-semibold text-xs">
                    <span className="w-2 h-2 rounded-full bg-teal-400"></span>
                    <span>3. Modèle du K-Anonymat</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Seuls les <strong>5 premiers caractères</strong> du hash SHA-1 sont transmis pour interroger la base mondiale. Il est mathématiquement et cryptographiquement impossible pour quiconque de retrouver votre mot de passe à partir de ces 5 caractères.
                  </p>
                </div>
              </div>

              {/* Collapsible Step-by-Step Diagram */}
              {disclaimerExpanded && (
                <div className="mt-3 p-3.5 sm:p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 animate-in fade-in duration-200">
                  <div className="flex items-center space-x-2 text-slate-200 font-bold text-xs">
                    <Cpu className="w-4 h-4 text-emerald-400" />
                    <span>Fonctionnement détaillé du K-Anonymat (Protocole cryptographique HIBP / Cloudflare) :</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5 text-[11px]">
                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80 space-y-1">
                      <span className="font-mono text-emerald-400 font-bold block">1. Saisie locale</span>
                      <p className="text-slate-400 leading-relaxed">
                        Le mot de passe reste confiné dans la mémoire locale de votre appareil (smartphone ou PC).
                      </p>
                    </div>

                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80 space-y-1">
                      <span className="font-mono text-cyan-400 font-bold block">2. Hachage SHA-1 local</span>
                      <p className="text-slate-400 leading-relaxed">
                        Votre navigateur calcule instantanément l'empreinte de 40 caractères hexadécimaux : <span className="font-mono text-slate-300">5BAA6...8FD8</span>.
                      </p>
                    </div>

                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80 space-y-1">
                      <span className="font-mono text-amber-400 font-bold block">3. Préfixe public seul</span>
                      <p className="text-slate-400 leading-relaxed">
                        Seuls les 5 premiers caractères (<span className="font-mono text-emerald-300 font-bold">5BAA6</span>) sont interrogés. Le serveur distant retourne des centaines d'empreintes anonymisées ayant ce même préfixe.
                      </p>
                    </div>

                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80 space-y-1">
                      <span className="font-mono text-teal-400 font-bold block">4. Filtrage privé en mémoire</span>
                      <p className="text-slate-400 leading-relaxed">
                        Votre appareil compare en toute discrétion les 35 caractères restants. Personne d'autre n'a eu accès à votre mot de passe.
                      </p>
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-emerald-950/30 border border-emerald-900/40 text-[11px] text-emerald-300 flex items-center space-x-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>
                      <strong>Conformité DSI & RGPD :</strong> Application stricte du principe de minimisation des données (Art. 5 du RGPD) et des recommandations de l'ANSSI pour les outils d'audit de sécurité.
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: GENERATOR */}
        {activeTab === 'generator' && (
          <div className="max-w-3xl mx-auto space-y-5 sm:space-y-6">
            <div className="text-center space-y-1.5">
              <h2 className="text-2xl sm:text-3xl font-extrabold text-white flex items-center justify-center space-x-2">
                <KeyRound className="w-6 h-6 sm:w-8 sm:h-8 text-emerald-400" />
                <span>Générateur Cryptographique</span>
              </h2>
              <p className="text-slate-400 text-xs sm:text-sm">
                Créez des clés haute entropie et vérifiez en temps réel via K-Anonymat qu'elles n'ont jamais été compromises.
              </p>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 sm:p-8 space-y-5 shadow-xl">
              {/* Generated Output */}
              <div className="p-3.5 sm:p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-3">
                <div className="text-xs text-slate-400 flex items-center justify-between">
                  <span>Mot de passe généré :</span>
                  {genPwnedCheck === false && (
                    <span className="text-emerald-400 text-[11px] sm:text-xs font-mono flex items-center space-x-1">
                      <ShieldCheck className="w-3.5 h-3.5" />
                      <span>Vierge de fuite</span>
                    </span>
                  )}
                </div>
                <div className="text-base sm:text-2xl font-mono text-emerald-300 break-all select-all font-semibold py-1">
                  {generatedPassword}
                </div>
                <div className="flex items-center space-x-2 pt-1 border-t border-slate-800/80">
                  <button
                    onClick={generateNewPassword}
                    className="flex-1 py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors flex items-center justify-center space-x-1.5 cursor-pointer"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Régénérer</span>
                  </button>
                  <button
                    onClick={() => copyToClipboard(generatedPassword)}
                    className="flex-1 py-2 px-3 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs transition-colors flex items-center justify-center space-x-1.5 cursor-pointer"
                  >
                    {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copié !' : 'Copier'}</span>
                  </button>
                </div>
              </div>

              {/* Sliders & Controls */}
              <div className="space-y-4">
                <div>
                  <div className="flex items-center justify-between text-xs sm:text-sm font-medium text-slate-300 mb-2">
                    <span>Longueur : {genLength} caractères</span>
                    <span className="text-xs font-mono text-emerald-400">
                      {genLength >= 16 ? 'Sécurité Maximale' : genLength >= 12 ? 'Bonne Sécurité' : 'Sécurité Faible'}
                    </span>
                  </div>
                  <input
                    type="range"
                    min="10"
                    max="48"
                    value={genLength}
                    onChange={(e) => setGenLength(parseInt(e.target.value, 10))}
                    className="w-full accent-emerald-500 cursor-pointer h-2 bg-slate-800 rounded-lg"
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 sm:gap-3">
                  <label className="flex items-center space-x-3 p-3 rounded-xl bg-slate-950 border border-slate-800 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={genUpper}
                      onChange={(e) => setGenUpper(e.target.checked)}
                      className="rounded accent-emerald-500 w-4 h-4"
                    />
                    <span className="text-xs sm:text-sm text-slate-200">Majuscules (A-Z)</span>
                  </label>

                  <label className="flex items-center space-x-3 p-3 rounded-xl bg-slate-950 border border-slate-800 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={genNumbers}
                      onChange={(e) => setGenNumbers(e.target.checked)}
                      className="rounded accent-emerald-500 w-4 h-4"
                    />
                    <span className="text-xs sm:text-sm text-slate-200">Chiffres (0-9)</span>
                  </label>

                  <label className="flex items-center space-x-3 p-3 rounded-xl bg-slate-950 border border-slate-800 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={genSymbols}
                      onChange={(e) => setGenSymbols(e.target.checked)}
                      className="rounded accent-emerald-500 w-4 h-4"
                    />
                    <span className="text-xs sm:text-sm text-slate-200">Symboles (!@#$)</span>
                  </label>
                </div>
              </div>

              {/* Entropy and crack estimation */}
              <div className="p-3.5 sm:p-4 rounded-xl bg-slate-950 border border-slate-800/80 flex items-center justify-between text-xs sm:text-sm">
                <div>
                  <span className="text-[11px] sm:text-xs text-slate-400">Temps estimé de cassage :</span>
                  <div className="text-sm sm:text-base font-bold text-white mt-0.5">
                    {genLength >= 20 ? '+ de 300 millions d\'années' : genLength >= 14 ? '~85 000 années' : '~3 jours'}
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-[11px] sm:text-xs text-slate-400">Entropie :</span>
                  <div className="text-sm sm:text-base font-bold font-mono text-cyan-400 mt-0.5">
                    {Math.round(genLength * 6.5)} bits
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: BREACH DATABASE */}
        {activeTab === 'breaches' && (
          <div className="space-y-5 sm:space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h2 className="text-xl sm:text-2xl font-extrabold text-white flex items-center space-x-2">
                  <Database className="w-5 h-5 sm:w-6 sm:h-6 text-emerald-400" />
                  <span>Annuaire des Violations Majeures</span>
                </h2>
                <p className="text-slate-400 text-xs sm:text-sm mt-0.5">
                  Consultez les principales fuites mondiales et nationales documentées.
                </p>
              </div>

              {/* Search & Filter */}
              <div className="flex flex-col sm:flex-row gap-2">
                <div className="relative">
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Filtrer par nom..."
                    className="w-full sm:w-56 bg-slate-900 border border-slate-800 rounded-xl px-3.5 py-2 text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500"
                  />
                  <Search className="w-4 h-4 text-slate-500 absolute right-3 top-1/2 -translate-y-1/2" />
                </div>

                <select
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs sm:text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-emerald-500"
                >
                  <option value="ALL">Toutes catégories</option>
                  <option value="ComboList">Combo Lists & Dumps</option>
                  <option value="StealerLogs">Info-Stealers (Malwares)</option>
                  <option value="Social">Réseaux Sociaux</option>
                  <option value="Tech">Technologie & Cloud</option>
                  <option value="Entertainment">Divertissement</option>
                  <option value="Finance">Finance & Public</option>
                  <option value="Gaming">Jeux Vidéo</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 sm:gap-4">
              {filteredBreaches.map((breach) => (
                <div key={breach.id} className="p-4 sm:p-5 bg-slate-900/70 border border-slate-800 rounded-2xl space-y-2.5 hover:border-slate-700 transition-all">
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="text-base sm:text-lg font-bold text-white flex items-center space-x-2">
                        <span>{breach.name}</span>
                        {breach.isSensitive && (
                          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
                            Sensible
                          </span>
                        )}
                      </h3>
                      {breach.domain && <span className="text-xs font-mono text-emerald-400">{breach.domain}</span>}
                    </div>
                    <span className="text-[11px] font-mono text-slate-400">
                      {breach.breachDate}
                    </span>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">{breach.description}</p>

                  <div className="flex items-center justify-between text-xs pt-1 border-t border-slate-800">
                    <span className="text-slate-400 text-[11px]">Comptes :</span>
                    <span className="font-mono font-bold text-white text-[11px]">{breach.pwnCount.toLocaleString()}</span>
                  </div>

                  <div>
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Données exposées :</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {breach.dataClasses.map((dc, i) => (
                        <span key={i} className="text-[10px] sm:text-[11px] px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800">
                          {dc}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 4: THREAT INTELLIGENCE */}
        {activeTab === 'threats' && (
          <div className="space-y-5 sm:space-y-6">
            <div className="text-center max-w-2xl mx-auto space-y-1.5">
              <h2 className="text-2xl sm:text-3xl font-extrabold text-white flex items-center justify-center space-x-2">
                <Activity className="w-6 h-6 sm:w-8 sm:h-8 text-emerald-400" />
                <span>Centre de Menaces</span>
              </h2>
              <p className="text-slate-400 text-xs sm:text-sm">
                Statistiques consolidées des violations de sécurité, journaux de malwares et mots de passe les plus vulnérables.
              </p>
            </div>

            {/* Metrics Row - 2x2 on mobile, 4 columns on desktop */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-2.5 sm:gap-4">
              <div className="p-3.5 sm:p-5 bg-slate-900/80 border border-slate-800 rounded-2xl">
                <span className="text-[10px] sm:text-xs uppercase font-mono text-slate-400 block truncate">Comptes Indexés</span>
                <div className="text-xl sm:text-3xl font-extrabold text-white mt-1">14,92 Md</div>
                <span className="text-[10px] sm:text-xs text-emerald-400 mt-1 block">+120M ce mois</span>
              </div>

              <div className="p-3.5 sm:p-5 bg-slate-900/80 border border-slate-800 rounded-2xl">
                <span className="text-[10px] sm:text-xs uppercase font-mono text-slate-400 block truncate">Violations Suivies</span>
                <div className="text-xl sm:text-3xl font-extrabold text-cyan-400 mt-1">{CURRENT_STATS.monitoredBreachesCount}</div>
                <span className="text-[10px] sm:text-xs text-slate-500 mt-1 block">Vérifiées analystes</span>
              </div>

              <div className="p-3.5 sm:p-5 bg-slate-900/80 border border-slate-800 rounded-2xl">
                <span className="text-[10px] sm:text-xs uppercase font-mono text-slate-400 block truncate">Info-Stealers</span>
                <div className="text-xl sm:text-3xl font-extrabold text-rose-400 mt-1">184,5 M</div>
                <span className="text-[10px] sm:text-xs text-rose-400 mt-1 block truncate">RedLine, Lumma</span>
              </div>

              <div className="p-3.5 sm:p-5 bg-slate-900/80 border border-slate-800 rounded-2xl">
                <span className="text-[10px] sm:text-xs uppercase font-mono text-slate-400 block truncate">Synchronisation</span>
                <div className="text-lg sm:text-2xl font-extrabold text-slate-200 mt-1 truncate">{CURRENT_STATS.lastUpdated}</div>
                <span className="text-[10px] sm:text-xs text-emerald-400 mt-1 block">Flux actif</span>
              </div>
            </div>

            {/* Top Passwords & Data Types */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
              {/* Top Leaked Passwords */}
              <div className="p-4 sm:p-6 bg-slate-900/80 border border-slate-800 rounded-2xl space-y-3">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                  <h3 className="text-sm sm:text-base font-bold text-white flex items-center space-x-2">
                    <Flame className="w-4 h-4 text-rose-400" />
                    <span>Top Mots de Passe Compromis</span>
                  </h3>
                  <span className="text-[10px] text-slate-500 font-mono">Monde</span>
                </div>
                <div className="space-y-1.5">
                  {CURRENT_STATS.topPasswordsLeaked.map((item) => (
                    <div key={item.rank} className="flex items-center justify-between p-2 rounded-xl bg-slate-950 border border-slate-800/80 text-xs">
                      <div className="flex items-center space-x-2.5">
                        <span className="w-5 h-5 rounded-md bg-slate-900 flex items-center justify-center text-[10px] font-mono font-bold text-slate-400">
                          #{item.rank}
                        </span>
                        <span className="font-mono text-rose-300 font-semibold">{item.password}</span>
                      </div>
                      <span className="text-[11px] font-mono text-slate-400">
                        {item.count.toLocaleString()}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Data Types */}
              <div className="p-4 sm:p-6 bg-slate-900/80 border border-slate-800 rounded-2xl space-y-3">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                  <h3 className="text-sm sm:text-base font-bold text-white flex items-center space-x-2">
                    <Globe2 className="w-4 h-4 text-cyan-400" />
                    <span>Typologie des Données Exposées</span>
                  </h3>
                  <span className="text-[10px] text-slate-500 font-mono">% fuites</span>
                </div>
                <div className="space-y-2.5">
                  {CURRENT_STATS.compromisedDataTypes.map((item, idx) => (
                    <div key={idx} className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-300 font-medium text-[11px] sm:text-xs">{item.name}</span>
                        <span className="text-slate-400 font-mono text-[10px] sm:text-xs">{item.percentage}%</span>
                      </div>
                      <div className="h-1.5 sm:h-2 rounded-full bg-slate-950 overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-emerald-500 to-cyan-500 rounded-full"
                          style={{ width: `${item.percentage}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: REMEDIATION & ACTION PLAN */}
        {activeTab === 'remediation' && (
          <div className="max-w-3xl mx-auto space-y-5 sm:space-y-6">
            <div className="text-center space-y-1.5">
              <h2 className="text-2xl sm:text-3xl font-extrabold text-white flex items-center justify-center space-x-2">
                <ListChecks className="w-6 h-6 sm:w-8 sm:h-8 text-emerald-400" />
                <span>Protocole de Réaction</span>
              </h2>
              <p className="text-slate-400 text-xs sm:text-sm">
                Checklist d'incident response pour sécuriser immédiatement vos comptes personnels et professionnels.
              </p>
            </div>

            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 sm:p-8 space-y-3 shadow-xl">
              {[
                {
                  id: 'check-1',
                  title: '1. Remplacer en priorité le mot de passe compromis',
                  desc: 'Si vous avez réutilisé ce mot de passe sur d\'autres services (e-mail, banque, réseaux sociaux), changez-le immédiatement partout en utilisant un gestionnaire de mots de passe.'
                },
                {
                  id: 'check-2',
                  title: '2. Activer l\'authentification multifacteur (2FA)',
                  desc: 'Préférez une application TOTP (Google Authenticator, Aegis, Bitwarden) ou des clés de sécurité matérielles (YubiKey / Passkeys) plutôt que le SMS, vulnérable au SIM-swapping.'
                },
                {
                  id: 'check-3',
                  title: '3. Révoquer les sessions actives et cookies',
                  desc: 'Dans les paramètres de vos comptes, déconnectez tous les appareils actifs pour invalider d\'éventuels jetons de session volés par des Info-Stealers.'
                },
                {
                  id: 'check-4',
                  title: '4. Vérifier les règles de transfert d\'e-mails',
                  desc: 'Les pirates créent souvent des filtres ou des redirections discrètes dans votre boîte mail pour intercepter vos codes de récupération.'
                },
                {
                  id: 'check-5',
                  title: '5. Surveiller vos comptes bancaires et le phishing',
                  desc: 'Méfiez-vous des SMS et appels urgents (faux conseillers bancaires, livraisons de colis). Ne communiquez JAMAIS de code reçu par SMS.'
                },
                {
                  id: 'check-6',
                  title: '6. Analyser votre ordinateur avec un antimalware réputé',
                  desc: 'Si vos identifiants proviennent de Stealer Logs (comme Naz.API ou RedLine), effectuez une analyse complète pour éliminer tout cheval de Troie actif.'
                }
              ].map((step) => {
                const isChecked = checklist[step.id] || false;
                return (
                  <div
                    key={step.id}
                    onClick={() => toggleChecklist(step.id)}
                    className={`p-3.5 sm:p-4 rounded-xl border transition-all cursor-pointer flex items-start space-x-3 ${
                      isChecked
                        ? 'bg-emerald-950/20 border-emerald-800/60 text-slate-300'
                        : 'bg-slate-950 border-slate-800 text-slate-100 hover:border-slate-700'
                    }`}
                  >
                    <div className={`w-5 h-5 rounded-md flex items-center justify-center shrink-0 mt-0.5 border ${
                      isChecked ? 'bg-emerald-500 border-emerald-400 text-slate-950' : 'border-slate-600 bg-slate-900'
                    }`}>
                      {isChecked && <Check className="w-3.5 h-3.5 stroke-[3]" />}
                    </div>
                    <div className="space-y-0.5">
                      <h4 className={`text-sm sm:text-base font-bold ${isChecked ? 'line-through text-slate-400' : 'text-white'}`}>
                        {step.title}
                      </h4>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        {step.desc}
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

      </main>

      {/* Footer - with safe padding for mobile bottom nav */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-6 pb-24 md:pb-6 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-4">
          <div className="flex flex-col sm:flex-row items-center sm:items-start space-y-2 sm:space-y-0 sm:space-x-3 text-center sm:text-left">
            <div className="bg-white/95 px-2.5 py-1.5 rounded-xl border border-slate-700/60 flex items-center shrink-0">
              <img
                src="/assets/aistudio/LOGO-GSO-FONCE_365c143b.png"
                alt="Groupe Sud Ouest"
                className="h-6 sm:h-7 w-auto object-contain"
              />
            </div>
            <div className="space-y-1">
              <div className="flex flex-wrap items-center justify-center sm:justify-start gap-x-2">
                <span className="font-semibold text-slate-300">CyberLeak Guard</span>
                <span>— Plateforme de détection et prévention des fuites d'identifiants</span>
                <span className="font-mono text-[10px] uppercase px-1.5 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/60">
                  v1.1
                </span>
              </div>
              <div className="text-emerald-400 font-mono text-xs font-semibold">
                DSI 2026 • Groupe Sud Ouest
              </div>
            </div>
          </div>

          <div className="text-slate-400 font-mono text-center sm:text-right text-[11px]">
            K-Anonymity SHA-1 Protocol • Aucune donnée en clair transmise
          </div>
        </div>
      </footer>

      {/* Sticky Bottom Navigation Bar for Smartphones */}
      <nav className="fixed bottom-0 left-0 right-0 z-50 md:hidden bg-slate-950/95 border-t border-slate-800/90 backdrop-blur-xl px-1.5 py-1.5 flex items-center justify-around shadow-2xl">
        <button
          onClick={() => setActiveTab('scanner')}
          className={`flex flex-col items-center justify-center py-1 px-2 rounded-xl transition-all ${
            activeTab === 'scanner'
              ? 'text-emerald-400 font-bold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Search className="w-5 h-5 mb-0.5" />
          <span className="text-[10px]">Scanner</span>
        </button>

        <button
          onClick={() => setActiveTab('generator')}
          className={`flex flex-col items-center justify-center py-1 px-2 rounded-xl transition-all ${
            activeTab === 'generator'
              ? 'text-emerald-400 font-bold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <KeyRound className="w-5 h-5 mb-0.5" />
          <span className="text-[10px]">Générateur</span>
        </button>

        <button
          onClick={() => setActiveTab('breaches')}
          className={`flex flex-col items-center justify-center py-1 px-2 rounded-xl transition-all ${
            activeTab === 'breaches'
              ? 'text-emerald-400 font-bold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Database className="w-5 h-5 mb-0.5" />
          <span className="text-[10px]">Fuites</span>
        </button>

        <button
          onClick={() => setActiveTab('threats')}
          className={`flex flex-col items-center justify-center py-1 px-2 rounded-xl transition-all ${
            activeTab === 'threats'
              ? 'text-emerald-400 font-bold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-5 h-5 mb-0.5" />
          <span className="text-[10px]">Menaces</span>
        </button>

        <button
          onClick={() => setActiveTab('remediation')}
          className={`flex flex-col items-center justify-center py-1 px-2 rounded-xl transition-all ${
            activeTab === 'remediation'
              ? 'text-emerald-400 font-bold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <ListChecks className="w-5 h-5 mb-0.5" />
          <span className="text-[10px]">Plan</span>
        </button>
      </nav>
    </div>
  );
}
