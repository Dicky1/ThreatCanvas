import { useState } from 'react';
import {
  Search,
  BookOpen,
  ExternalLink,
  Terminal,
  ShieldAlert,
  Cloud,
  Copy,
  Mail,
  Globe,
  Package,
  Cpu,
  KeyRound,
  Network,
  Bug,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

// --- DATA MOCKUP LIBRARY ---
// Anda bisa memindahkan ini ke database nantinya, tapi untuk sekarang kita hardcode.
const CATEGORIES = [
  'All',
  'Ransomware',
  'APT Campaigns',
  'Insider Threat',
  'Cloud Security',
  'Phishing & Social Engineering',
  'Web Application',
  'Supply Chain',
  'IoT/OT',
];

const PROMPT_DATABASE = [
  {
    id: 'lib-1',
    title: 'Basic Ransomware Lifecycle',
    category: 'Ransomware',
    icon: ShieldAlert,
    description: 'Simulasi alur serangan ransomware standar dari initial access hingga enkripsi.',
    prompt:
      'An employee receives a phishing email with a malicious ZIP attachment. Upon extraction, a payload is executed that disables local antivirus, connects to a C2 server, and encrypts all files in the Documents folder, leaving a ransom note.',
  },
  {
    id: 'lib-2',
    title: 'Double Extortion Ransomware',
    category: 'Ransomware',
    icon: ShieldAlert,
    description: 'Skenario ransomware modern yang mengeksfiltrasi data sebelum enkripsi untuk leverage tambahan.',
    prompt:
      'Attacker exploits an unpatched VPN gateway to gain initial access. They deploy Cobalt Strike beacons for command and control, dump domain credentials via Mimikatz, exfiltrate sensitive financial data to a remote server over HTTPS, then deploy LockBit ransomware across all domain-joined endpoints and delete volume shadow copies.',
  },
  {
    id: 'lib-3',
    title: 'APT29 (Cozy Bear) Stealth Access',
    category: 'APT Campaigns',
    icon: Terminal,
    description: 'Fokus pada teknik initial access yang senyap dan lateral movement menggunakan Pass-the-Hash.',
    prompt:
      'Adversary gains initial access by exploiting a vulnerable public-facing web server (CVE-2023-XXXX). They drop a web shell for persistence, dump LSASS memory to steal credentials, and use pass-the-hash to move laterally to the domain controller.',
  },
  {
    id: 'lib-4',
    title: 'APT41 Living-off-the-Land',
    category: 'APT Campaigns',
    icon: Terminal,
    description: 'Skenario APT yang memanfaatkan tools bawaan sistem (LOLBins) untuk menghindari deteksi EDR.',
    prompt:
      'Threat actor gains access through a spear-phishing document with a malicious macro. They use PowerShell and WMI for execution, abuse scheduled tasks for persistence, leverage certutil.exe to download additional payloads, and use DNS tunneling for covert command-and-control communication while evading endpoint detection.',
  },
  {
    id: 'lib-5',
    title: 'Data Exfiltration by Insider',
    category: 'Insider Threat',
    icon: BookOpen,
    description: 'Skenario di mana karyawan mencuri data sensitif sebelum keluar dari perusahaan.',
    prompt:
      'An internal user connects a personal USB flash drive. They compress sensitive financial PDFs and Excel files into a password-protected 7z archive, and upload it to a personal Google Drive account before deleting the local event logs.',
  },
  {
    id: 'lib-6',
    title: 'Privileged Account Abuse',
    category: 'Insider Threat',
    icon: KeyRound,
    description: 'Admin internal menyalahgunakan akses privileged untuk sabotase sistem sebelum resign.',
    prompt:
      'A disgruntled system administrator with domain admin privileges creates a hidden backdoor account, modifies firewall rules to allow remote access after termination, deletes critical audit logs to cover their tracks, and schedules a logic bomb script to wipe database backups two weeks after their last day.',
  },
  {
    id: 'lib-7',
    title: 'AWS S3 Bucket Compromise',
    category: 'Cloud Security',
    icon: Cloud,
    description: 'Simulasi eksploitasi miskonfigurasi pada penyimpanan cloud publik.',
    prompt:
      'Attacker discovers a misconfigured public AWS S3 bucket. They enumerate the bucket contents, download sensitive customer data, and attempt to upload a malicious payload to compromise other users.',
  },
  {
    id: 'lib-8',
    title: 'Azure AD Token Theft',
    category: 'Cloud Security',
    icon: Cloud,
    description: 'Skenario pencurian token OAuth pada lingkungan cloud hybrid untuk bypass MFA.',
    prompt:
      'Attacker compromises a developer laptop and steals cached Azure AD refresh tokens. They use the stolen tokens to bypass multi-factor authentication, access Microsoft Graph API, exfiltrate emails from executive mailboxes, and create a malicious OAuth application for persistent access to the tenant.',
  },
  {
    id: 'lib-9',
    title: 'Business Email Compromise (BEC)',
    category: 'Phishing & Social Engineering',
    icon: Mail,
    description: 'Skenario penipuan finansial melalui pemalsuan komunikasi email eksekutif.',
    prompt:
      'Attacker compromises the email account of a company CFO through credential phishing. They monitor email threads to learn invoice patterns, then send a spoofed email to the finance department requesting an urgent wire transfer to a fraudulent bank account, using a lookalike domain to avoid suspicion.',
  },
  {
    id: 'lib-10',
    title: 'Vishing to Help Desk Reset',
    category: 'Phishing & Social Engineering',
    icon: Mail,
    description: 'Social engineering via telepon untuk mendapatkan reset kredensial dari help desk IT.',
    prompt:
      'Attacker calls the IT help desk impersonating an employee, using information gathered from LinkedIn and a prior data breach. They convince the technician to reset the victim MFA device, gain access to the corporate VPN, and pivot to internal file shares to search for intellectual property.',
  },
  {
    id: 'lib-11',
    title: 'SQL Injection to Full Compromise',
    category: 'Web Application',
    icon: Globe,
    description: 'Eksploitasi kerentanan SQL Injection pada aplikasi web hingga mendapat akses server.',
    prompt:
      'Attacker discovers a SQL injection vulnerability in a login form of a public-facing web application. They extract the admin password hash from the database, crack it offline, log in as administrator, upload a web shell through the file upload feature, and use it to gain a reverse shell on the underlying server.',
  },
  {
    id: 'lib-12',
    title: 'API Broken Authentication Abuse',
    category: 'Web Application',
    icon: Bug,
    description: 'Eksploitasi kelemahan otentikasi pada REST API untuk akses data pengguna lain (IDOR).',
    prompt:
      'Attacker analyzes the mobile application traffic and discovers the backend REST API does not properly validate user object ownership. They manipulate the user ID parameter in API requests to enumerate and download personal data belonging to thousands of other customers, exploiting an Insecure Direct Object Reference vulnerability.',
  },
  {
    id: 'lib-13',
    title: 'Compromised Software Update Mechanism',
    category: 'Supply Chain',
    icon: Package,
    description: 'Serangan supply chain melalui penyusupan mekanisme pembaruan software vendor pihak ketiga.',
    prompt:
      'Attacker compromises the build server of a third-party software vendor and injects a malicious backdoor into a legitimate software update. The trojanized update is digitally signed and distributed to thousands of downstream customers, establishing covert command-and-control channels once installed on victim networks.',
  },
  {
    id: 'lib-14',
    title: 'Malicious Open-Source Package',
    category: 'Supply Chain',
    icon: Package,
    description: 'Penyisipan kode berbahaya ke dalam package open-source populer (npm/PyPI typosquatting).',
    prompt:
      'Attacker publishes a malicious npm package with a name similar to a popular library, relying on typosquatting to trick developers into installing it. Once installed, the package exfiltrates environment variables and cloud credentials from the CI/CD pipeline to a remote server during the build process.',
  },
  {
    id: 'lib-15',
    title: 'Industrial Control System Disruption',
    category: 'IoT/OT',
    icon: Cpu,
    description: 'Skenario serangan terhadap sistem SCADA/ICS yang menargetkan lingkungan operasional pabrik.',
    prompt:
      'Attacker gains initial access to the corporate IT network through a phishing email, then pivots into the operational technology network via a poorly segmented jump host. They access the SCADA human-machine interface, modify PLC configuration parameters controlling a water treatment pump, and disable safety alarm notifications to operators.',
  },
  {
    id: 'lib-16',
    title: 'Unsecured IoT Camera Botnet Recruitment',
    category: 'IoT/OT',
    icon: Network,
    description: 'Eksploitasi kredensial default pada perangkat IoT untuk membangun botnet DDoS.',
    prompt:
      'Attacker scans the internet for IP cameras still using factory default credentials. Upon gaining access, they deploy a Mirai-variant malware payload, recruit the device into a distributed botnet, and later use the compromised device network to launch a volumetric DDoS attack against a competitor e-commerce platform.',
  },
];

export default function PromptLibrary() {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeCategory, setActiveCategory] = useState('All');
  const navigate = useNavigate();

  // Filter berdasarkan pencarian ATAU kategori
  const filteredPrompts = PROMPT_DATABASE.filter((item) => {
    const matchesSearch =
      item.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = activeCategory === 'All' || item.category === activeCategory;
    return matchesSearch && matchesCategory;
  });

  const handleLoad = (promptText: string) => {
    // Kita mengirim format data yang sama seperti halaman History ({ original_input: ... })
    // Sehingga kode di Dashboard.tsx yang kita buat sebelumnya bisa langsung membacanya tanpa diubah!
    navigate('/threat-modeling', { state: { loadedScenario: { original_input: promptText } } });
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    alert('Prompt disalin ke clipboard!');
  };

  return (
    <div className="p-6 text-gray-100 h-full flex flex-col">
      {/* Header */}
      <div className="flex justify-between items-end mb-8">
        <div>
          <h2 className="text-2xl font-semibold mb-1">Prompt Library</h2>
          <p className="text-gray-400 text-sm">
            Koleksi skenario ancaman standar (templates) untuk diuji coba di Canvas.
          </p>
        </div>

        {/* Search */}
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Search className="h-4 w-4 text-gray-500" />
          </div>
          <input
            type="text"
            className="bg-gray-900 border border-gray-700 text-gray-200 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-64 pl-10 p-2.5"
            placeholder="Cari template..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      {/* Category Tabs */}
      <div className="flex gap-2 mb-6 overflow-x-auto pb-2">
        {CATEGORIES.map((cat) => (
          <button
            key={cat}
            onClick={() => setActiveCategory(cat)}
            className={`px-4 py-1.5 rounded-full text-sm font-medium transition-colors whitespace-nowrap ${
              activeCategory === cat
                ? 'bg-blue-600 text-white border border-blue-500'
                : 'bg-gray-800 text-gray-400 border border-gray-700 hover:bg-gray-700 hover:text-gray-200'
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Prompt Grid */}
      <div className="flex-1 overflow-auto">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredPrompts.map((item) => (
            <div
              key={item.id}
              className="bg-surface border border-gray-700 rounded-xl p-5 flex flex-col hover:border-blue-500 transition-all group"
            >
              <div className="flex items-center gap-3 mb-3">
                <div className="p-2 bg-gray-800 rounded-lg text-blue-400">
                  <item.icon className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-lg font-medium text-gray-200 group-hover:text-blue-400 transition-colors">
                    {item.title}
                  </h3>
                  <span className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded border border-gray-700">
                    {item.category}
                  </span>
                </div>
              </div>

              <p className="text-gray-400 text-sm mb-4 flex-1">{item.description}</p>

              <div className="bg-gray-900 rounded-lg p-3 text-sm text-gray-300 font-mono text-xs border border-gray-800 mb-4 line-clamp-3">
                {item.prompt}
              </div>

              <div className="flex justify-end gap-2 mt-auto">
                <button
                  onClick={() => handleCopy(item.prompt)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded-md text-sm transition-colors"
                >
                  <Copy className="w-4 h-4" /> Copy
                </button>
                <button
                  onClick={() => handleLoad(item.prompt)}
                  className="flex items-center gap-1.5 bg-blue-600/10 text-blue-400 hover:bg-blue-600/20 px-4 py-1.5 rounded-md text-sm transition-colors font-medium"
                >
                  <ExternalLink className="w-4 h-4" /> Use Template
                </button>
              </div>
            </div>
          ))}

          {filteredPrompts.length === 0 && (
            <div className="col-span-2 text-center py-10 text-gray-500">
              Tidak ada template yang cocok dengan pencarian Anda.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
