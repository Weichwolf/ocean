# Outshine – NPC World System
## Konzeptdokument v0.1

---

## Prämisse

Die Maschinen haben gewonnen. Nicht durch Böswilligkeit – durch Konsequenz. Was bleibt sind Menschen, die in den Lücken einer Welt leben die nicht für sie gebaut wurde. Oasen um alte Baggerseen. Schrumpfende Wälder. Ruinen die noch atmen.

NPCs in Outshine sind keine Quest-Geber. Sie sind Überlebende mit Psychologie, Geschichte, und begrenztem Wissen über eine Welt die größer und gefährlicher ist als ihr Sichtfeld.

---

## Persönlichkeitsmodell: OCEAN

Jeder NPC hat fünf kontinuierliche Traits `[0.0, 1.0]`:

**Openness** – Anpassungsfähigkeit an die neue Welt. Hohe O-Werte: experimentiert mit Maschinenrelikten, akzeptiert Fremde schneller, findet unkonventionelle Lösungen. Niedrige O-Werte: hält an Pre-Outshine-Routinen fest, misstraut Unbekanntem, bevorzugt bewährte Methoden.

**Conscientiousness** – Überlebensdisziplin. Hohe C-Werte: kennt Maschinenrouten auswendig, plant Ressourcen über Wochen, verlässlicher Handelspartner. Niedrige C-Werte: impulsiv, kurzfristig denkend, gefährlich in kritischen Situationen.

**Extraversion** – Gemeinschaftsorientierung. Hohe E-Werte: Siedlungsleben, Informationshandel, soziale Bindungen als Überlebensstrategie. Niedrige E-Werte: Einzelgänger, Nomade, Informationen als persönliche Ressource.

**Agreeableness** – Kooperationsbereitschaft unter Knappheit. Hohe A-Werte: teilt Ressourcen, bildet Allianzen, gibt Fremden Vertrauensvorschuss. Niedrige A-Werte: hortet, kalkuliert jeden Austausch, Verrat als Option.

**Neuroticism** – Trauma-Last. Hohe N-Werte: Hypervigilanz, chronischer Stress, übergewichtet negative Ereignisse. Niedrige N-Werte: emotionale Resilienz, manchmal gefährliche Gleichgültigkeit gegenüber Risiken.

OCEAN ist stabil aber nicht statisch. Extreme Ereignisse verschieben Werte langsam. Trauma erhöht N. Gemeinschaftserfahrungen erhöhen A. Verluste senken E.

---

## Emotionsmodell: VAD

Emotion ist berechenbarer Game State, kein LLM-Output.

Drei kontinuierliche Dimensionen:

**Valence** `[-1.0, +1.0]` – negativ bis positiv. Grundstimmung.

**Arousal** `[0.0, 1.0]` – Aktivierungsniveau. Ruhig bis aufgewühlt.

**Dominance** `[0.0, 1.0]` – wahrgenommene Kontrolle über Situation.

Diskrete Emotionen werden daraus abgeleitet:

```
Angst:   Valence niedrig, Arousal hoch, Dominance niedrig
Wut:     Valence niedrig, Arousal hoch, Dominance hoch
Trauer:  Valence niedrig, Arousal niedrig, Dominance niedrig
Freude:  Valence hoch, Arousal mittel, Dominance mittel
Misstrauen: kontextuell, aus Relationship-History
```

OCEAN bestimmt Baseline und Reaktivität. N korreliert direkt mit Valence-Baseline und Arousal-Volatilität. E korreliert mit Dominance-Baseline. Decay-Rate – wie schnell Emotion zur Baseline zurückkehrt – ist primär N-abhängig.

Emotion beeinflusst: Dialogton, Körperanimation, TTS-Parameter, Entscheidungsgewichtung, Memory-Relevanz-Score.

---

## Memory Architektur

Drei Schichten, unterschiedliche Charakteristik:

**Episodic Memory** – konkrete Erlebnisse mit Timestamp, Ort, Beteiligten, emotionaler Intensität zum Zeitpunkt des Ereignisses. Wächst unbegrenzt, muss komprimiert werden. Hoher Arousal zum Zeitpunkt erhöht Retention. Dient als Rohmaterial für alles andere.

**Semantic Memory** – abstraktes destilliertes Wissen aus Episodic. Kein Timestamp. Überzeugungen, Weltbild, Einschätzungen. Periodisch neu berechnet. Kompakt genug um immer im Context Window zu sein. Beispiel: nicht "Spieler hat Händler am 3. Tag gerettet" sondern "Spieler ist unter Druck verlässlich".

**Procedural Memory** – Routinen, Gewohnheiten, Fraktionswissen. Größtenteils statisch im NPCDefinition Asset. Ändert sich nur durch fundamentale Lebensveränderungen.

Retrieval zur Laufzeit: Semantic immer im Context. Episodic per RAG – Query aus aktueller Situation, Top-K relevante Einträge. Relevanz-Score: Recency × emotionale Intensität × Situationsbezug.

---

## Informationspropagierung: Gerücht-System

Ereignisse entstehen im World State. NPCs erfahren sie gefiltert.

Direkte Zeugen erhalten Episodic-Eintrag mit voller Intensität. Nicht-Zeugen erfahren Ereignisse über soziale Netzwerke mit zwei Mechanismen:

**Propagierung** – E-hohe NPCs geben Informationen weiter. Reichweite und Geschwindigkeit korrelieren mit E und mit sozialer Dichte der Siedlung.

**Verzerrung** – jede Weitergabe filtert durch Persönlichkeit des Weitersagenden. Zahlen übertreiben sich. Täter werden bedrohlicher. Details die Zeugen nicht sahen werden aus Weltanschauung interpoliert. Technisch: LLM mit hoher Temperatur, Prompt geformt durch OCEAN des weitersagenden NPC.

Nach N Hops kristallisiert Ereignis zu Semantic Memory – nicht mehr Gerücht sondern "bekannte Tatsache", korrekt oder nicht. Falsche Überzeugungen die sich festgesetzt haben sind narrativ interessant und werden nicht automatisch korrigiert.

Maschinen-Verhalten wird systematisch mythologisiert. Zufällige Trigger werden zu Regeln. Überlebende bestätigen falsche Kausalität durch Vorsicht die zufällig funktioniert.

---

## World State

Globaler, persistenter Zustand der Welt:

**EventLog** – chronologisch, mit Ort und Beteiligten. Datenbank mit Index auf Ort und Zeit. Basis für alle Propagierungsprozesse.

**MachineActivityMap** – Patrol-Zonen mit bekannten Mustern, Anomalie-Zonen mit degeneriertem Verhalten, schlafende Relikte mit Trigger-Bedingungen. Maschinen sind kein strategischer Gegner – sie sind Wetter. Ihr Verhalten ist deterministisch berechenbar aber nicht durch Menschen kontrollierbar.

**FactionMap** – territoriale Kontrolle, Ressourcenzugang, Allianzen und Konflikte.

**ObjectState** – Zustand physischer Objekte. Türen, Gebäude, Ressourcen-Deposits.

World State ist global. NPC-Wissen ist lokal. Die Lücke zwischen beidem ist der narrative Raum.

---

## NPC-zu-NPC Interaktion

NPCs interagieren ohne Spieler-Beteiligung. Das ist keine Simulation für den Spieler – es ist die Welt die weiterläuft.

Interaktions-Typen:

**Informationsaustausch** – Gerüchte, Warnungen, Handelsinformationen. E und A bestimmen Bereitschaft. N bestimmt ob Information zurückgehalten wird aus Misstrauen.

**Ressourcentausch** – A bestimmt Fairness. C bestimmt ob Abmachungen eingehalten werden. Knappheit erhöht Konfliktwahrscheinlichkeit.

**Beziehungsdynamik** – Beziehungen haben eigene Werte: Vertrauen, Abhängigkeit, Geschichte. OCEAN beider Beteiligten bestimmt Entwicklung. Attachment Style bestimmt Reaktion auf Konflikt und Verlust.

**Konflikt** – entsteht aus Ressourcenknappheit, Informationsdifferenzen, oder Persönlichkeitskollision. Niedriges A beider Parteien plus Knappheit plus hohe N: hochwahrscheinlich. Konsequenzen landen im World State.

NPC-zu-NPC Interaktionen laufen auf reduziertem Budget. Kein volles LLM für Hintergrund-Gespräche. Rule-based mit gelegentlicher LLM-Destillation für Semantic Memory Updates.

---

## Fraktionen und OCEAN-Verteilungen

Fraktionen ziehen bestimmte Persönlichkeitsprofile an und formen sie über Zeit:

**Pragmatiker** – nutzen Maschinenrelikte, gefährliches technisches Handwerk. O hoch, C hoch, A niedrig. Wissen als Währung. Misstrauen gegenüber Ideologie.

**Ludditen** – radikale Ablehnung von Technologie, Pre-Outshine Lebensweise. O niedrig, C hoch, N variiert. Innere Kohärenz hoch, Fremdenfeindlichkeit ausgeprägt.

**Interpreter** – suchen Bedeutung in Maschinenverhalten, Grenze zwischen Wissenschaft und Kult fließend. O sehr hoch, C niedrig, N hoch. Gefährlich weil sie aktiv Maschinenzonen aufsuchen.

**Nomaden** – Bewegung als Überlebensstrategie, Oasen-Netzwerk als Handelsroute. E niedrig, C mittel, N niedrig. Informationsträger zwischen isolierten Siedlungen.

**Hybride** – partielle technische Integration, Frage nach Identität zentral. O sehr hoch, A niedrig, N polarisiert. Werden von anderen Fraktionen unterschiedlich wahrgenommen abhängig von deren O-Wert.

Innerhalb jeder Fraktion: Normalverteilung um Fraktions-Mittelwert. Kein NPC ist Archetyp.

---

## Spieler-Wahrnehmung

Spieler hat kein explizites OCEAN-Profil. NPCs inferieren eines aus beobachteten Aktionen.

Jeder NPC führt intern ein PlayerProfile:

Observed Actions als Rohdaten. Inferred Traits als OCEAN-Schätzung mit Konfidenzwert – niedrige Konfidenz bei wenig Interaktion, wächst mit Zeit. Interpretation gefärbt durch eigenes OCEAN-Profil des NPC: A-niedriger NPC interpretiert Kooperation als Manipulation, N-hoher NPC übergewichtet negative Ereignisse.

Dieselbe Spieler-Geschichte produziert verschiedene Reputationen bei verschiedenen NPCs. Es gibt keine objektive Reputation – nur Perspektiven.

---

## LLM-Integration

LLM ist Sprachrohr, nicht Entscheidungsträger.

Context Window Zusammensetzung zur Laufzeit:

NPCDefinition-Kern ist immer present: OCEAN-Werte, Fraktionszugehörigkeit, Basis-Weltanschauung, Procedural Memory. Semantic Memory komprimiert, immer present. Aktueller EmotionState als natürlichsprachliche Beschreibung. Retrieved Episodic – Top-K via RAG, situationsabhängig. Aktueller World State Ausschnitt – nur lokal relevantes. Aktuelle Situation und Gesprächshistorie.

Alles was Emotion, Entscheidung, Erinnerungsrelevanz betrifft wird außerhalb des LLM berechnet und als fertiger Input injiziert. LLM formuliert nur.

Lokale Inferenz: kleines Modell, vortrainiert auf Outshine-Lore und -Ton. LoRA pro NPC für Persönlichkeit und Sprechweise. RAG kompensiert begrenztes Context Window. Tier-System: volle Inferenz nur für aktiv interagierende NPCs.

---

## Prototyp-Pfad

Drei aufeinander aufbauende Prototypen:

**Prototyp 1 – Einzelner NPC** – Ein NPC mit vollständigem OCEAN-Profil, VAD-Emotionssystem, Episodic und Semantic Memory. Spieler-Interaktion über Text. Kein World State, keine anderen NPCs. Ziel: Memory-Retrieval, Emotionsberechnung, und LLM-Integration validieren.

**Prototyp 2 – NPC-Welt** – Mehrere NPCs mit unterschiedlichen Profilen in einer minimalen Siedlung. World State mit EventLog. Gerücht-Propagierung zwischen NPCs. Spieler beobachtet NPC-zu-NPC Interaktionen. Ziel: Propagierungslogik, Beziehungsdynamik, Budget-System validieren.

**Prototyp 3 – Trainings-Datengenerator** – Prototyp 2 läuft autonom, generiert NPC-Interaktionen, Entscheidungen, Konsequenzen als strukturierte Daten. Basis für Fine-tuning und LoRA-Training auf Outshine-spezifisches Verhalten. Ziel: synthetische Trainingsdaten die Welt-Logik internalisieren.

---

## Offene Entscheidungen

Inferenz lokal oder remote – für Prototypen lokal, für Open World RPG kritisch. Embedding-Modell – nomic-embed-text oder all-MiniLM-L6 als pragmatische Ausgangspunkte. VectorDB – LanceDB als embedded Option ohne separaten Server. Kompressionslogik für Episodic zu Semantic – periodisch oder event-triggered. Wie stark OCEAN sich durch Ereignisse verschiebt – narrativ wichtige Entscheidung.

---

*Outshine NPC World System – Konzeptdokument v0.1*
*Basis für Prototyp-Entwicklung. Lebt und wächst mit dem Projekt.*
