import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card.jsx'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Textarea } from '@/components/ui/textarea.jsx'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.jsx'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table.jsx'
import { Progress } from '@/components/ui/progress.jsx'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert.jsx'
import { 
  Shield, 
  Search, 
  FileText, 
  Clock, 
  AlertTriangle, 
  CheckCircle, 
  Upload, 
  Download, 
  Settings, 
  Eye,
  Database,
  Activity,
  Globe,
  Hash,
  Calendar,
  BarChart3,
  Filter,
  RefreshCw,
  Plus,
  Trash2,
  Edit
} from 'lucide-react'
import './App.css'

function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [investigations, setInvestigations] = useState([
    {
      id: 1,
      name: 'INCIDENT-RANSOMWARE-2025',
      status: 'active',
      created: '2025-01-20',
      artifacts: 12,
      iocs: 8,
      lastActivity: '2025-01-20 14:30'
    },
    {
      id: 2,
      name: 'PHISHING-CAMPAIGN-Q1',
      status: 'completed',
      created: '2025-01-15',
      artifacts: 5,
      iocs: 15,
      lastActivity: '2025-01-18 09:15'
    }
  ])
  
  const [currentInvestigation, setCurrentInvestigation] = useState(investigations[0])
  const [iocs, setIocs] = useState([
    { type: 'IP', value: '192.168.1.100', source: 'auth.log', reputation: 'malicious', score: 8 },
    { type: 'Domain', value: 'malicious-site.com', source: 'firewall.csv', reputation: 'suspicious', score: 6 },
    { type: 'Hash', value: 'a1b2c3d4e5f6...', source: 'system.evtx', reputation: 'clean', score: 2 }
  ])
  
  const [timeline, setTimeline] = useState([
    { timestamp: '2025-01-20 08:15:32', event: 'Tentative de connexion suspecte détectée', severity: 'high' },
    { timestamp: '2025-01-20 08:20:15', event: 'Échec d\'authentification multiple', severity: 'medium' },
    { timestamp: '2025-01-20 08:25:44', event: 'Accès non autorisé au système', severity: 'critical' }
  ])

  const [analysisProgress, setAnalysisProgress] = useState(0)
  const [isAnalyzing, setIsAnalyzing] = useState(false)

  const startAnalysis = () => {
    setIsAnalyzing(true)
    setAnalysisProgress(0)
    
    const interval = setInterval(() => {
      setAnalysisProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval)
          setIsAnalyzing(false)
          return 100
        }
        return prev + 10
      })
    }, 500)
  }

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-500'
      case 'high': return 'bg-orange-500'
      case 'medium': return 'bg-yellow-500'
      case 'low': return 'bg-blue-500'
      default: return 'bg-gray-500'
    }
  }

  const getReputationColor = (reputation) => {
    switch (reputation) {
      case 'malicious': return 'destructive'
      case 'suspicious': return 'secondary'
      case 'clean': return 'default'
      default: return 'outline'
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-orange-500" />
              <div>
                <h1 className="text-2xl font-bold text-white">Phoenix DFIR</h1>
                <p className="text-sm text-gray-400">Assistant d'Investigation Forensique</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <Badge variant="outline" className="text-green-400 border-green-400">
                <Activity className="h-3 w-3 mr-1" />
                Système Actif
              </Badge>
              <Button variant="ghost" size="sm">
                <Settings className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-6">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-6 bg-gray-900 border border-gray-800">
            <TabsTrigger value="dashboard" className="data-[state=active]:bg-orange-500 data-[state=active]:text-white">
              <BarChart3 className="h-4 w-4 mr-2" />
              Dashboard
            </TabsTrigger>
            <TabsTrigger value="investigations" className="data-[state=active]:bg-orange-500 data-[state=active]:text-white">
              <Database className="h-4 w-4 mr-2" />
              Enquêtes
            </TabsTrigger>
            <TabsTrigger value="analyzer" className="data-[state=active]:bg-orange-500 data-[state=active]:text-white">
              <Search className="h-4 w-4 mr-2" />
              Analyseur
            </TabsTrigger>
            <TabsTrigger value="timeline" className="data-[state=active]:bg-orange-500 data-[state=active]:text-white">
              <Clock className="h-4 w-4 mr-2" />
              Timeline
            </TabsTrigger>
            <TabsTrigger value="iocs" className="data-[state=active]:bg-orange-500 data-[state=active]:text-white">
              <AlertTriangle className="h-4 w-4 mr-2" />
              IoCs
            </TabsTrigger>
            <TabsTrigger value="reports" className="data-[state=active]:bg-orange-500 data-[state=active]:text-white">
              <FileText className="h-4 w-4 mr-2" />
              Rapports
            </TabsTrigger>
          </TabsList>

          {/* Dashboard Tab */}
          <TabsContent value="dashboard" className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <Card className="bg-gray-900 border-gray-800">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-gray-300">Enquêtes Actives</CardTitle>
                  <Database className="h-4 w-4 text-orange-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-white">2</div>
                  <p className="text-xs text-gray-400">+1 cette semaine</p>
                </CardContent>
              </Card>
              
              <Card className="bg-gray-900 border-gray-800">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-gray-300">IoCs Détectés</CardTitle>
                  <AlertTriangle className="h-4 w-4 text-red-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-white">23</div>
                  <p className="text-xs text-gray-400">8 critiques</p>
                </CardContent>
              </Card>
              
              <Card className="bg-gray-900 border-gray-800">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-gray-300">Artefacts Analysés</CardTitle>
                  <FileText className="h-4 w-4 text-blue-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-white">17</div>
                  <p className="text-xs text-gray-400">Dernières 24h</p>
                </CardContent>
              </Card>
              
              <Card className="bg-gray-900 border-gray-800">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-gray-300">Taux de Détection</CardTitle>
                  <CheckCircle className="h-4 w-4 text-green-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-white">94%</div>
                  <p className="text-xs text-gray-400">Précision IA</p>
                </CardContent>
              </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="bg-gray-900 border-gray-800">
                <CardHeader>
                  <CardTitle className="text-white">Enquête Active</CardTitle>
                  <CardDescription className="text-gray-400">
                    {currentInvestigation.name}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Statut:</span>
                    <Badge variant="default" className="bg-green-600">Actif</Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Artefacts:</span>
                    <span className="text-white">{currentInvestigation.artifacts}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">IoCs:</span>
                    <span className="text-white">{currentInvestigation.iocs}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Dernière activité:</span>
                    <span className="text-white">{currentInvestigation.lastActivity}</span>
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-gray-900 border-gray-800">
                <CardHeader>
                  <CardTitle className="text-white">Activité Récente</CardTitle>
                  <CardDescription className="text-gray-400">
                    Derniers événements détectés
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {timeline.slice(0, 3).map((event, index) => (
                      <div key={index} className="flex items-start space-x-3">
                        <div className={`w-2 h-2 rounded-full mt-2 ${getSeverityColor(event.severity)}`} />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-white font-medium">{event.event}</p>
                          <p className="text-xs text-gray-400">{event.timestamp}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Investigations Tab */}
          <TabsContent value="investigations" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">Gestion des Enquêtes</h2>
              <Button className="bg-orange-600 hover:bg-orange-700">
                <Plus className="h-4 w-4 mr-2" />
                Nouvelle Enquête
              </Button>
            </div>

            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-white">Enquêtes</CardTitle>
                <CardDescription className="text-gray-400">
                  Liste de toutes les investigations forensiques
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow className="border-gray-800">
                      <TableHead className="text-gray-300">Nom</TableHead>
                      <TableHead className="text-gray-300">Statut</TableHead>
                      <TableHead className="text-gray-300">Créée le</TableHead>
                      <TableHead className="text-gray-300">Artefacts</TableHead>
                      <TableHead className="text-gray-300">IoCs</TableHead>
                      <TableHead className="text-gray-300">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {investigations.map((investigation) => (
                      <TableRow key={investigation.id} className="border-gray-800">
                        <TableCell className="text-white font-medium">{investigation.name}</TableCell>
                        <TableCell>
                          <Badge variant={investigation.status === 'active' ? 'default' : 'secondary'}>
                            {investigation.status === 'active' ? 'Actif' : 'Terminé'}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-gray-300">{investigation.created}</TableCell>
                        <TableCell className="text-gray-300">{investigation.artifacts}</TableCell>
                        <TableCell className="text-gray-300">{investigation.iocs}</TableCell>
                        <TableCell>
                          <div className="flex space-x-2">
                            <Button variant="ghost" size="sm">
                              <Eye className="h-4 w-4" />
                            </Button>
                            <Button variant="ghost" size="sm">
                              <Edit className="h-4 w-4" />
                            </Button>
                            <Button variant="ghost" size="sm">
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Analyzer Tab */}
          <TabsContent value="analyzer" className="space-y-6">
            <h2 className="text-2xl font-bold text-white">Analyseur de Fichiers</h2>
            
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="bg-gray-900 border-gray-800">
                <CardHeader>
                  <CardTitle className="text-white">Upload de Fichier</CardTitle>
                  <CardDescription className="text-gray-400">
                    Glissez-déposez vos artefacts pour analyse
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="border-2 border-dashed border-gray-700 rounded-lg p-8 text-center hover:border-orange-500 transition-colors">
                    <Upload className="h-12 w-12 text-gray-500 mx-auto mb-4" />
                    <p className="text-gray-400 mb-2">Glissez vos fichiers ici ou cliquez pour sélectionner</p>
                    <p className="text-xs text-gray-500">Formats supportés: EVTX, CSV, JSON, LOG, TXT</p>
                    <Button variant="outline" className="mt-4">
                      Sélectionner des fichiers
                    </Button>
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="analysis-query" className="text-gray-300">Question d'analyse</Label>
                    <Textarea 
                      id="analysis-query"
                      placeholder="Décrivez ce que vous recherchez dans ce fichier..."
                      className="bg-gray-800 border-gray-700 text-white"
                    />
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="file-type" className="text-gray-300">Type de fichier</Label>
                      <Select>
                        <SelectTrigger className="bg-gray-800 border-gray-700 text-white">
                          <SelectValue placeholder="Auto-détection" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="auto">Auto-détection</SelectItem>
                          <SelectItem value="evtx">EVTX (Windows Logs)</SelectItem>
                          <SelectItem value="csv">CSV</SelectItem>
                          <SelectItem value="json">JSON</SelectItem>
                          <SelectItem value="log">LOG/TXT</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div className="space-y-2">
                      <Label htmlFor="event-id" className="text-gray-300">Event ID (EVTX)</Label>
                      <Input 
                        id="event-id"
                        placeholder="4625, 4624..."
                        className="bg-gray-800 border-gray-700 text-white"
                      />
                    </div>
                  </div>
                  
                  <Button 
                    onClick={startAnalysis} 
                    disabled={isAnalyzing}
                    className="w-full bg-orange-600 hover:bg-orange-700"
                  >
                    {isAnalyzing ? (
                      <>
                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                        Analyse en cours...
                      </>
                    ) : (
                      <>
                        <Search className="h-4 w-4 mr-2" />
                        Lancer l'analyse
                      </>
                    )}
                  </Button>
                  
                  {isAnalyzing && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-400">Progression</span>
                        <span className="text-white">{analysisProgress}%</span>
                      </div>
                      <Progress value={analysisProgress} className="bg-gray-800" />
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card className="bg-gray-900 border-gray-800">
                <CardHeader>
                  <CardTitle className="text-white">Résultats d'Analyse</CardTitle>
                  <CardDescription className="text-gray-400">
                    Dernière analyse effectuée
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {analysisProgress === 100 ? (
                    <div className="space-y-4">
                      <Alert className="border-green-600 bg-green-950">
                        <CheckCircle className="h-4 w-4" />
                        <AlertTitle className="text-green-400">Analyse terminée</AlertTitle>
                        <AlertDescription className="text-green-300">
                          3 nouveaux IoCs détectés dans le fichier auth.log
                        </AlertDescription>
                      </Alert>
                      
                      <div className="space-y-3">
                        <h4 className="font-medium text-white">IoCs découverts:</h4>
                        <div className="space-y-2">
                          <div className="flex items-center justify-between p-2 bg-gray-800 rounded">
                            <span className="text-white">192.168.1.100</span>
                            <Badge variant="destructive">Malveillant</Badge>
                          </div>
                          <div className="flex items-center justify-between p-2 bg-gray-800 rounded">
                            <span className="text-white">suspicious-domain.com</span>
                            <Badge variant="secondary">Suspect</Badge>
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <Search className="h-12 w-12 text-gray-600 mx-auto mb-4" />
                      <p className="text-gray-400">Aucune analyse en cours</p>
                      <p className="text-sm text-gray-500">Uploadez un fichier pour commencer</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Timeline Tab */}
          <TabsContent value="timeline" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">Timeline des Événements</h2>
              <div className="flex space-x-2">
                <Button variant="outline" size="sm">
                  <Filter className="h-4 w-4 mr-2" />
                  Filtrer
                </Button>
                <Button variant="outline" size="sm">
                  <Download className="h-4 w-4 mr-2" />
                  Exporter
                </Button>
              </div>
            </div>

            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-white">Chronologie</CardTitle>
                <CardDescription className="text-gray-400">
                  Événements ordonnés chronologiquement
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {timeline.map((event, index) => (
                    <div key={index} className="flex items-start space-x-4 p-4 bg-gray-800 rounded-lg">
                      <div className="flex flex-col items-center">
                        <div className={`w-3 h-3 rounded-full ${getSeverityColor(event.severity)}`} />
                        {index < timeline.length - 1 && (
                          <div className="w-px h-8 bg-gray-700 mt-2" />
                        )}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <p className="text-white font-medium">{event.event}</p>
                          <Badge variant={getReputationColor(event.severity)}>
                            {event.severity}
                          </Badge>
                        </div>
                        <p className="text-sm text-gray-400 mt-1">
                          <Calendar className="h-3 w-3 inline mr-1" />
                          {event.timestamp}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* IoCs Tab */}
          <TabsContent value="iocs" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">Indicateurs de Compromission</h2>
              <Button className="bg-orange-600 hover:bg-orange-700">
                <Plus className="h-4 w-4 mr-2" />
                Ajouter IoC
              </Button>
            </div>

            <Card className="bg-gray-900 border-gray-800">
              <CardHeader>
                <CardTitle className="text-white">IoCs Détectés</CardTitle>
                <CardDescription className="text-gray-400">
                  Indicateurs enrichis automatiquement via VirusTotal
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow className="border-gray-800">
                      <TableHead className="text-gray-300">Type</TableHead>
                      <TableHead className="text-gray-300">Valeur</TableHead>
                      <TableHead className="text-gray-300">Source</TableHead>
                      <TableHead className="text-gray-300">Réputation</TableHead>
                      <TableHead className="text-gray-300">Score</TableHead>
                      <TableHead className="text-gray-300">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {iocs.map((ioc, index) => (
                      <TableRow key={index} className="border-gray-800">
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            {ioc.type === 'IP' && <Globe className="h-4 w-4 text-blue-400" />}
                            {ioc.type === 'Domain' && <Globe className="h-4 w-4 text-green-400" />}
                            {ioc.type === 'Hash' && <Hash className="h-4 w-4 text-purple-400" />}
                            <span className="text-white">{ioc.type}</span>
                          </div>
                        </TableCell>
                        <TableCell className="text-white font-mono text-sm">{ioc.value}</TableCell>
                        <TableCell className="text-gray-300">{ioc.source}</TableCell>
                        <TableCell>
                          <Badge variant={getReputationColor(ioc.reputation)}>
                            {ioc.reputation}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            <span className="text-white">{ioc.score}/10</span>
                            <div className="w-16 h-2 bg-gray-700 rounded-full">
                              <div 
                                className={`h-full rounded-full ${
                                  ioc.score >= 7 ? 'bg-red-500' : 
                                  ioc.score >= 4 ? 'bg-yellow-500' : 'bg-green-500'
                                }`}
                                style={{ width: `${ioc.score * 10}%` }}
                              />
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex space-x-2">
                            <Button variant="ghost" size="sm">
                              <Eye className="h-4 w-4" />
                            </Button>
                            <Button variant="ghost" size="sm">
                              <Download className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Reports Tab */}
          <TabsContent value="reports" className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">Génération de Rapports</h2>
              <Button className="bg-orange-600 hover:bg-orange-700">
                <FileText className="h-4 w-4 mr-2" />
                Nouveau Rapport
              </Button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="bg-gray-900 border-gray-800">
                <CardHeader>
                  <CardTitle className="text-white">Configuration du Rapport</CardTitle>
                  <CardDescription className="text-gray-400">
                    Personnalisez votre rapport d'investigation
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="report-title" className="text-gray-300">Titre du rapport</Label>
                    <Input 
                      id="report-title"
                      value={currentInvestigation.name}
                      className="bg-gray-800 border-gray-700 text-white"
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="report-template" className="text-gray-300">Template</Label>
                    <Select>
                      <SelectTrigger className="bg-gray-800 border-gray-700 text-white">
                        <SelectValue placeholder="Sélectionner un template" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="executive">Résumé Exécutif</SelectItem>
                        <SelectItem value="technical">Rapport Technique</SelectItem>
                        <SelectItem value="forensic">Analyse Forensique</SelectItem>
                        <SelectItem value="incident">Rapport d'Incident</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="report-format" className="text-gray-300">Format de sortie</Label>
                    <Select>
                      <SelectTrigger className="bg-gray-800 border-gray-700 text-white">
                        <SelectValue placeholder="Sélectionner le format" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="html">HTML</SelectItem>
                        <SelectItem value="pdf">PDF</SelectItem>
                        <SelectItem value="markdown">Markdown</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <div className="space-y-2">
                    <Label className="text-gray-300">Sections à inclure</Label>
                    <div className="space-y-2">
                      {[
                        'Résumé exécutif',
                        'Timeline des événements',
                        'IoCs détectés',
                        'Artefacts analysés',
                        'Recommandations'
                      ].map((section) => (
                        <div key={section} className="flex items-center space-x-2">
                          <input 
                            type="checkbox" 
                            defaultChecked 
                            className="rounded border-gray-700 bg-gray-800"
                          />
                          <span className="text-gray-300 text-sm">{section}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  
                  <Button className="w-full bg-orange-600 hover:bg-orange-700">
                    <FileText className="h-4 w-4 mr-2" />
                    Générer le Rapport
                  </Button>
                </CardContent>
              </Card>

              <Card className="bg-gray-900 border-gray-800">
                <CardHeader>
                  <CardTitle className="text-white">Prévisualisation</CardTitle>
                  <CardDescription className="text-gray-400">
                    Aperçu du rapport généré
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="bg-gray-800 p-4 rounded-lg space-y-4 max-h-96 overflow-y-auto">
                    <div className="border-b border-gray-700 pb-2">
                      <h3 className="text-lg font-bold text-white">{currentInvestigation.name}</h3>
                      <p className="text-sm text-gray-400">Rapport d'Investigation Forensique</p>
                    </div>
                    
                    <div>
                      <h4 className="font-medium text-white mb-2">Résumé Exécutif</h4>
                      <p className="text-sm text-gray-300 leading-relaxed">
                        Cette investigation a révélé des activités suspectes liées à une tentative 
                        d'intrusion sur le système. L'analyse des logs a permis d'identifier plusieurs 
                        indicateurs de compromission critiques nécessitant une action immédiate.
                      </p>
                    </div>
                    
                    <div>
                      <h4 className="font-medium text-white mb-2">Statistiques</h4>
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-400">IoCs détectés:</span>
                          <span className="text-white font-medium">{iocs.length}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Événements:</span>
                          <span className="text-white font-medium">{timeline.length}</span>
                        </div>
                      </div>
                    </div>
                    
                    <div>
                      <h4 className="font-medium text-white mb-2">IoCs Critiques</h4>
                      <div className="space-y-1">
                        {iocs.filter(ioc => ioc.score >= 7).map((ioc, index) => (
                          <div key={index} className="text-sm text-gray-300 font-mono">
                            • {ioc.value} ({ioc.type})
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  )
}

export default App
