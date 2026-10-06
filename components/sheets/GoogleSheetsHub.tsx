'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  FileSpreadsheet,
  FolderSearch,
  Plus,
  RefreshCw,
  Upload,
  Download,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  LogOut,
  Table,
  Layers,
  Save,
  Eraser,
} from 'lucide-react';
import type { User } from 'firebase/auth';
import {
  initAuth,
  googleSignIn,
  getAccessToken,
  logout as googleLogout,
} from '@/lib/google-auth';
import { GoogleSignInButton } from '@/components/site/GoogleSignInButton';
import { useUyanixStore, StudentLeader } from '@/lib/store';
import { getTopicsForClass, MCQQuestion } from '@/lib/curriculum';
import { toast } from 'sonner';

interface DriveSpreadsheetFile {
  id: string;
  name: string;
  modifiedTime?: string;
  webViewLink?: string;
  owners?: { displayName?: string; emailAddress?: string }[];
}

interface SheetTabProperty {
  sheetId: number;
  title: string;
}

interface PendingConfirmation {
  title: string;
  description: string;
  affectedCountLabel: string;
  confirmLabel: string;
  variant: 'primary' | 'destructive';
  onConfirm: () => Promise<void>;
}

function extractSpreadsheetId(input: string): string {
  const trimmed = input.trim();
  const match = trimmed.match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/);
  if (match && match[1]) {
    return match[1];
  }
  return trimmed;
}

export function GoogleSheetsHub() {
  const {
    leaderboard,
    customExamQuestions,
    savedChapters,
    teachers,
    withdrawals,
    bulkImportExamQuestions,
    importLeaderboardFromSheet,
    bulkSaveChapters,
    login,
  } = useUyanixStore();

  const [needsAuth, setNeedsAuth] = useState(true);
  const [googleUser, setGoogleUser] = useState<User | null>(null);
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  // Drive spreadsheets browser state
  const [driveFiles, setDriveFiles] = useState<DriveSpreadsheetFile[]>([]);
  const [driveSearch, setDriveSearch] = useState('');
  const [loadingDrive, setLoadingDrive] = useState(false);

  // Active spreadsheet & sheet tabs state
  const [spreadsheetInput, setSpreadsheetInput] = useState('');
  const [activeSpreadsheetId, setActiveSpreadsheetId] = useState('');
  const [activeSpreadsheetTitle, setActiveSpreadsheetTitle] = useState('');
  const [activeSpreadsheetUrl, setActiveSpreadsheetUrl] = useState('');
  const [sheetTabs, setSheetTabs] = useState<SheetTabProperty[]>([]);
  const [selectedTab, setSelectedTab] = useState('');

  // Active grid values
  const [gridRows, setGridRows] = useState<string[][]>([]);
  const [loadingSheet, setLoadingSheet] = useState(false);
  const [newSheetTitle, setNewSheetTitle] = useState(
    'Uyanix 30 Days Challenge — Master Sheet'
  );
  const [creatingSheet, setCreatingSheet] = useState(false);

  // New row quick-append state
  const [newRowCells, setNewRowCells] = useState<string[]>(['', '', '', '', '']);

  // Confirmation modal state for mutating/destructive operations (MANDATORY)
  const [pendingConfirmation, setPendingConfirmation] =
    useState<PendingConfirmation | null>(null);
  const [executingConfirm, setExecutingConfirm] = useState(false);

  const fetchDriveSpreadsheets = useCallback(async (searchQuery = '') => {
    const token = await getAccessToken();
    if (!token) {
      setNeedsAuth(true);
      return;
    }

    setLoadingDrive(true);
    try {
      const url = new URL('/api/drive', window.location.origin);
      if (searchQuery.trim()) {
        url.searchParams.set('q', searchQuery.trim());
      }
      const res = await fetch(url.toString(), {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.status === 401) {
        setNeedsAuth(true);
        return;
      }
      if (!res.ok) {
        throw new Error(data.error || 'Could not load Google Drive spreadsheets');
      }
      setDriveFiles(data.files || []);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Failed to list spreadsheets';
      toast.error(message);
    } finally {
      setLoadingDrive(false);
    }
  }, []);

  const fetchTabValues = useCallback(
    async (spreadsheetId: string, tabName: string) => {
      const token = await getAccessToken();
      if (!token) {
        setNeedsAuth(true);
        return;
      }

      setLoadingSheet(true);
      try {
        const res = await fetch(
          `/api/sheets?spreadsheetId=${encodeURIComponent(
            spreadsheetId
          )}&range=${encodeURIComponent(tabName)}`,
          {
            headers: { Authorization: `Bearer ${token}` },
          }
        );
        const data = await res.json();
        if (res.status === 401) {
          setNeedsAuth(true);
          return;
        }
        if (!res.ok) {
          throw new Error(data.error || 'Failed to read sheet values');
        }
        const values: string[][] = data.values || [];
        setGridRows(values);
        const colCount = Math.max(5, values[0]?.length || 5);
        setNewRowCells(Array.from({ length: colCount }, () => ''));
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : 'Failed to load tab values';
        toast.error(message);
      } finally {
        setLoadingSheet(false);
      }
    },
    []
  );

  const loadSpreadsheetMetadata = useCallback(
    async (rawIdOrUrl: string) => {
      const spreadsheetId = extractSpreadsheetId(rawIdOrUrl);
      if (!spreadsheetId) {
        toast.error('Please enter or select a valid Google Spreadsheet.');
        return;
      }

      const token = await getAccessToken();
      if (!token) {
        setNeedsAuth(true);
        return;
      }

      setLoadingSheet(true);
      try {
        const res = await fetch(
          `/api/sheets?spreadsheetId=${encodeURIComponent(spreadsheetId)}`,
          {
            headers: { Authorization: `Bearer ${token}` },
          }
        );
        const data = await res.json();
        if (res.status === 401) {
          setNeedsAuth(true);
          return;
        }
        if (!res.ok) {
          throw new Error(data.error || 'Failed to fetch spreadsheet metadata');
        }

        const tabs: SheetTabProperty[] = (data.sheets || []).map(
          (s: { properties: { sheetId: number; title: string } }) => ({
            sheetId: s.properties.sheetId,
            title: s.properties.title,
          })
        );

        setActiveSpreadsheetId(spreadsheetId);
        setActiveSpreadsheetTitle(
          data.properties?.title || 'Untitled Spreadsheet'
        );
        setActiveSpreadsheetUrl(
          data.spreadsheetUrl ||
            `https://docs.google.com/spreadsheets/d/${spreadsheetId}/edit`
        );
        setSheetTabs(tabs);

        if (tabs.length > 0) {
          const firstTab = tabs[0].title;
          setSelectedTab(firstTab);
          await fetchTabValues(spreadsheetId, firstTab);
        } else {
          setSelectedTab('');
          setGridRows([]);
        }
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : 'Could not open spreadsheet';
        toast.error(message);
      } finally {
        setLoadingSheet(false);
      }
    },
    [fetchTabValues]
  );

  useEffect(() => {
    const unsubscribe = initAuth(
      (user) => {
        setGoogleUser(user);
        setNeedsAuth(false);
        fetchDriveSpreadsheets('');
      },
      () => {
        setGoogleUser(null);
        setNeedsAuth(true);
      }
    );
    return () => unsubscribe();
  }, [fetchDriveSpreadsheets]);

  const handleGoogleLogin = async () => {
    setIsLoggingIn(true);
    try {
      const result = await googleSignIn();
      if (result) {
        setGoogleUser(result.user);
        setNeedsAuth(false);
        if (result.serverUser) {
          login(result.serverUser);
        }
        toast.success(
          `Connected to Google Workspace as ${
            result.user.email || result.user.displayName
          }! 📊`
        );
        await fetchDriveSpreadsheets('');
      }
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Google Sign-In failed';
      toast.error(message);
    } finally {
      setIsLoggingIn(false);
    }
  };

  const handleGoogleDisconnect = async () => {
    await googleLogout();
    setGoogleUser(null);
    setNeedsAuth(true);
    setDriveFiles([]);
    setActiveSpreadsheetId('');
    setSheetTabs([]);
    setGridRows([]);
    toast.info('Disconnected from Google Workspace.');
  };

  // Create a new master Uyanix spreadsheet with Leaderboard, ExamQuestions, Chapters, Teachers tabs
  const handleCreateMasterSpreadsheet = async () => {
    const token = await getAccessToken();
    if (!token) {
      setNeedsAuth(true);
      return;
    }

    setCreatingSheet(true);
    try {
      const leaderboardRows = [
        ['Rank', 'Student ID', 'Name', 'Class', 'City', 'Score', 'Total', 'Prize Status', 'School', 'Email'],
        ...leaderboard.map((s) => [
          String(s.rank),
          s.id,
          s.name,
          String(s.classNum),
          s.city,
          String(s.score),
          String(s.total),
          s.prizePaid ? 'Paid' : 'Pending',
          s.school || 'DPS',
          s.email || '',
        ]),
      ];

      const res = await fetch('/api/sheets', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          action: 'create',
          title:
            newSheetTitle.trim() ||
            `Uyanix 30 Days Challenge (${new Date().toISOString().slice(0, 10)})`,
          sheets: ['Leaderboard', 'ExamQuestions', 'Chapters', 'Teachers'],
          range: 'Leaderboard!A1',
          values: leaderboardRows,
        }),
      });

      const created = await res.json();
      if (res.status === 401) {
        setNeedsAuth(true);
        return;
      }
      if (!res.ok) {
        throw new Error(created.error || 'Failed to create spreadsheet');
      }

      toast.success(
        `Created "${created.properties?.title}" in your Google Drive! 🎉`
      );
      await fetchDriveSpreadsheets(driveSearch);
      await loadSpreadsheetMetadata(created.spreadsheetId);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Failed to create master sheet';
      toast.error(message);
    } finally {
      setCreatingSheet(false);
    }
  };

  // Request confirmation before mutating/overwriting Google Sheet data
  const requestSheetOverwriteConfirm = (
    actionLabel: string,
    rowsToWrite: string[][],
    targetTab = selectedTab
  ) => {
    if (!activeSpreadsheetId || !targetTab) {
      toast.error('Please select or create a Google Spreadsheet and tab first.');
      return;
    }

    setPendingConfirmation({
      title: `Update Google Sheet Tab "${targetTab}"?`,
      description: `This will overwrite existing cells in "${activeSpreadsheetTitle}" → tab "${targetTab}" with ${actionLabel}.`,
      affectedCountLabel: `${rowsToWrite.length} row(s) (${Math.max(
        0,
        rowsToWrite.length - 1
      )} data records + header row)`,
      confirmLabel: 'Confirm & Write to Sheet',
      variant: 'primary',
      onConfirm: async () => {
        const token = await getAccessToken();
        if (!token) {
          setNeedsAuth(true);
          return;
        }
        const res = await fetch('/api/sheets', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            action: 'update',
            spreadsheetId: activeSpreadsheetId,
            range: targetTab,
            values: rowsToWrite,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'Failed to update spreadsheet');
        }
        setGridRows(rowsToWrite);
        toast.success(
          `Synced ${rowsToWrite.length} rows to "${targetTab}" in Google Sheets! ✅`
        );
      },
    });
  };

  // Sync Leaderboard -> Active Sheet Tab
  const handleExportLeaderboardToSheet = () => {
    const rows: string[][] = [
      ['Rank', 'Student ID', 'Name', 'Class', 'City', 'Score', 'Total', 'Prize Status', 'School', 'Email'],
      ...leaderboard.map((s) => [
        String(s.rank),
        s.id,
        s.name,
        String(s.classNum),
        s.city,
        String(s.score),
        String(s.total),
        s.prizePaid ? 'Paid' : 'Pending',
        s.school || 'DPS',
        s.email || '',
      ]),
    ];
    requestSheetOverwriteConfirm('Uyanix Student Leaderboard data', rows);
  };

  // Sync Exam Questions Pool -> Active Sheet Tab
  const handleExportQuestionsToSheet = () => {
    const rows: string[][] = [
      [
        'ID',
        'Question',
        'Option A',
        'Option B',
        'Option C',
        'Option D',
        'Correct Option Index (0-3)',
        'Explanation',
        'Topic',
      ],
      ...customExamQuestions.map((q) => [
        q.id,
        q.question,
        q.options[0] || '',
        q.options[1] || '',
        q.options[2] || '',
        q.options[3] || '',
        String(q.correctIndex),
        q.explanation,
        q.topic || 'General Aptitude',
      ]),
    ];
    requestSheetOverwriteConfirm('Uyanix Mid & Final Exam MCQ Pool', rows);
  };

  // Sync 30-Day Curriculum Chapters -> Active Sheet Tab
  const handleExportChaptersToSheet = () => {
    const customEntries = Object.values(savedChapters);
    const defaultClass12 = getTopicsForClass(12).map((title, idx) => ({
      classNum: 12,
      day: idx + 1,
      title,
      content:
        savedChapters[`12-${idx + 1}`]?.content ||
        `NCERT Class 12 Day ${idx + 1}: ${title} core revision summary.`,
      updatedAt:
        savedChapters[`12-${idx + 1}`]?.updatedAt ||
        new Date().toISOString().slice(0, 10),
    }));

    const combined = customEntries.length > 0 ? customEntries : defaultClass12;
    const rows: string[][] = [
      ['Class', 'Day', 'Chapter Title', 'Study Material Content', 'Last Updated'],
      ...combined.map((c) => [
        String(c.classNum),
        String(c.day),
        c.title,
        c.content,
        c.updatedAt,
      ]),
    ];
    requestSheetOverwriteConfirm('Uyanix 30-Day Curriculum Chapters', rows);
  };

  // Sync Teachers & Payouts -> Active Sheet Tab
  const handleExportTeachersToSheet = () => {
    const rows: string[][] = [
      [
        'Teacher ID',
        'Name',
        'Email',
        'Referral Code',
        'Tier',
        'Status',
        'Referred Students',
        'Paid Active',
        'Wallet Balance (INR)',
        'Total Earned (INR)',
        'UPI ID',
      ],
      ...teachers.map((t) => [
        t.id,
        t.name,
        t.email,
        t.code,
        t.tier,
        t.status,
        String(t.referredCount),
        String(t.paidActiveCount),
        String(t.balance),
        String(t.totalEarned),
        t.upiId,
      ]),
      ...withdrawals.map((w) => [
        w.teacherId,
        w.teacherName,
        'PAYOUT_REQUEST',
        w.invoiceId,
        w.method,
        w.status,
        '-',
        '-',
        String(w.amount),
        w.date,
        w.destination,
      ]),
    ];
    requestSheetOverwriteConfirm('Teacher Referrals & Payouts Ledger', rows);
  };

  // Import from Active Sheet Tab -> Uyanix App Store
  const handleImportQuestionsFromSheet = () => {
    if (gridRows.length < 2) {
      toast.error(
        'Selected sheet tab needs a header row and at least 1 question row.'
      );
      return;
    }

    const dataRows = gridRows.slice(1);
    const parsedQuestions: MCQQuestion[] = dataRows
      .filter((r) => r.length >= 6 && (r[1] || r[0]))
      .map((r, idx): MCQQuestion => {
        // Support either [ID, Question, OptA, OptB, OptC, OptD, CorrectIdx, Explanation, Topic]
        // or [Question, OptA, OptB, OptC, OptD, CorrectIdx, Explanation, Topic]
        const hasIdCol = r.length >= 7 && (r[0]?.startsWith('q-') || r[0]?.startsWith('custom-') || r[0]?.startsWith('sheet-'));
        const offset = hasIdCol ? 1 : 0;
        const questionText = (r[offset] || '').trim();
        const optA = (r[offset + 1] || 'Option A').trim();
        const optB = (r[offset + 2] || 'Option B').trim();
        const optC = (r[offset + 3] || 'Option C').trim();
        const optD = (r[offset + 4] || 'Option D').trim();
        const rawCorrect = Number(r[offset + 5]);
        const correctIndex =
          !Number.isNaN(rawCorrect) && rawCorrect >= 0 && rawCorrect <= 3
            ? rawCorrect
            : 0;

        return {
          id: hasIdCol && r[0] ? r[0] : `sheet-q-${Date.now()}-${idx}`,
          question: questionText,
          options: [optA, optB, optC, optD] as [string, string, string, string],
          correctIndex,
          explanation:
            (r[offset + 6] || 'Imported from Google Sheets').trim(),
          topic: (r[offset + 7] || 'Google Sheets Pool').trim(),
        };
      })
      .filter((q) => q.question.length > 0);

    if (parsedQuestions.length === 0) {
      toast.error('No valid MCQ rows found in the current sheet tab.');
      return;
    }

    const added = bulkImportExamQuestions(parsedQuestions);
    toast.success(
      `Imported ${added} MCQ question(s) from Google Sheet "${selectedTab}" into Uyanix Exam Pool! 🎉`
    );
  };

  const handleImportLeaderboardFromSheet = () => {
    if (gridRows.length < 2) {
      toast.error(
        'Selected sheet tab needs a header row and at least 1 student row.'
      );
      return;
    }

    const parsedStudents: StudentLeader[] = gridRows
      .slice(1)
      .filter((r) => r.length >= 4 && (r[2] || r[1]))
      .map((r, idx) => ({
        rank: Number(r[0]) || idx + 1,
        id: r[1] || `sheet-st-${idx + 1}`,
        name: r[2] || `Student ${idx + 1}`,
        classNum: Math.min(12, Math.max(1, Number(r[3]) || 10)),
        city: r[4] || 'Jaipur',
        score: Number(r[5]) || 25,
        total: Number(r[6]) || 30,
        prizePaid: (r[7] || '').toLowerCase() === 'paid',
        school: r[8] || 'DPS',
        email: r[9] || '',
        status: 'active',
      }));

    if (parsedStudents.length === 0) {
      toast.error('No valid student rows found in this sheet tab.');
      return;
    }

    importLeaderboardFromSheet(parsedStudents);
    toast.success(
      `Imported ${parsedStudents.length} students from Google Sheets into Live Leaderboard! 🏆`
    );
  };

  const handleImportChaptersFromSheet = async () => {
    if (gridRows.length < 2) {
      toast.error(
        'Selected sheet tab needs a header row and at least 1 chapter row.'
      );
      return;
    }

    let totalImported = 0;
    const byClass: Record<
      number,
      { day: number; title: string; content: string }[]
    > = {};

    gridRows.slice(1).forEach((r) => {
      const cls = Math.min(12, Math.max(1, Number(r[0]) || 12));
      const day = Math.min(30, Math.max(1, Number(r[1]) || 1));
      const title = (r[2] || '').trim();
      const content = (r[3] || '').trim();
      if (!title) return;
      if (!byClass[cls]) byClass[cls] = [];
      byClass[cls].push({
        day,
        title,
        content: content || `Study material for Class ${cls} Day ${day}: ${title}`,
      });
    });

    for (const [clsStr, items] of Object.entries(byClass)) {
      totalImported += await bulkSaveChapters(Number(clsStr), items, true);
    }

    if (totalImported === 0) {
      toast.error('No valid chapter rows (Class, Day, Title, Content) found.');
      return;
    }

    toast.success(
      `Imported ${totalImported} daily chapter(s) from Google Sheets into Uyanix Curriculum! 📚`
    );
  };

  // Save edited grid directly to Google Sheet (with confirmation modal)
  const handleSaveEditedGrid = () => {
    requestSheetOverwriteConfirm('edited table cells', gridRows);
  };

  // Append a single row to active sheet tab (with confirmation modal)
  const handleAppendRow = (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeSpreadsheetId || !selectedTab) {
      toast.error('Select a spreadsheet and tab first.');
      return;
    }
    if (newRowCells.every((c) => !c.trim())) {
      toast.error('Enter at least one cell value to append.');
      return;
    }

    const rowToAppend = [...newRowCells];
    setPendingConfirmation({
      title: `Append Row to "${selectedTab}"?`,
      description: `This will add 1 new row [${rowToAppend
        .filter(Boolean)
        .join(', ')}] to the bottom of "${activeSpreadsheetTitle}" → "${selectedTab}".`,
      affectedCountLabel: '1 new row appended',
      confirmLabel: 'Confirm & Append Row',
      variant: 'primary',
      onConfirm: async () => {
        const token = await getAccessToken();
        if (!token) {
          setNeedsAuth(true);
          return;
        }
        const res = await fetch('/api/sheets', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            action: 'append',
            spreadsheetId: activeSpreadsheetId,
            range: selectedTab,
            values: [rowToAppend],
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'Failed to append row');
        }
        setGridRows((prev) => [...prev, rowToAppend]);
        setNewRowCells((prev) => prev.map(() => ''));
        toast.success(`Appended 1 row to "${selectedTab}"! ✅`);
      },
    });
  };

  // Clear active sheet tab (with confirmation modal)
  const handleClearActiveTab = () => {
    if (!activeSpreadsheetId || !selectedTab) return;
    setPendingConfirmation({
      title: `Clear All Cells in "${selectedTab}"?`,
      description: `Are you sure you want to clear all values in tab "${selectedTab}" of spreadsheet "${activeSpreadsheetTitle}"? This will wipe ${gridRows.length} row(s) from this tab.`,
      affectedCountLabel: `${gridRows.length} row(s) in "${selectedTab}" will be cleared`,
      confirmLabel: 'Clear Sheet Tab',
      variant: 'destructive',
      onConfirm: async () => {
        const token = await getAccessToken();
        if (!token) {
          setNeedsAuth(true);
          return;
        }
        const res = await fetch('/api/sheets', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            action: 'clear',
            spreadsheetId: activeSpreadsheetId,
            range: selectedTab,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'Failed to clear sheet tab');
        }
        setGridRows([]);
        toast.success(`Cleared all cells in "${selectedTab}".`);
      },
    });
  };

  // Delete a spreadsheet file from Google Drive (with confirmation modal)
  const handleDeleteDriveFile = (file: DriveSpreadsheetFile) => {
    setPendingConfirmation({
      title: `Delete "${file.name}" from Google Drive?`,
      description: `Are you sure you want to permanently delete "${file.name}" from your Google Drive? This action cannot be undone.`,
      affectedCountLabel: `1 Google Spreadsheet file ("${file.name}")`,
      confirmLabel: 'Delete Permanently',
      variant: 'destructive',
      onConfirm: async () => {
        const token = await getAccessToken();
        if (!token) {
          setNeedsAuth(true);
          return;
        }
        const res = await fetch(
          `/api/drive?fileId=${encodeURIComponent(file.id)}`,
          {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${token}` },
          }
        );
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || 'Failed to delete file');
        }
        setDriveFiles((prev) => prev.filter((f) => f.id !== file.id));
        if (activeSpreadsheetId === file.id) {
          setActiveSpreadsheetId('');
          setSheetTabs([]);
          setGridRows([]);
        }
        toast.success(`Deleted "${file.name}" from Google Drive.`);
      },
    });
  };

  const executeConfirmedAction = async () => {
    if (!pendingConfirmation) return;
    setExecutingConfirm(true);
    try {
      await pendingConfirmation.onConfirm();
      setPendingConfirmation(null);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Operation failed';
      toast.error(message);
    } finally {
      setExecutingConfirm(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Top Connection Banner */}
      <div className="rounded-3xl border border-border bg-card p-6 shadow-card sm:p-8">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-secondary/15 text-secondary">
              <FileSpreadsheet className="h-6 w-6" />
            </div>
            <div>
              <div className="inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-secondary">
                Google Workspace Integration • Live Sync
              </div>
              <h2 className="mt-0.5 text-2xl font-extrabold sm:text-3xl">
                Google Sheets &amp; Drive Data Hub
              </h2>
              <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
                Connect your Google Account to browse Drive spreadsheets, create
                a master Uyanix sheet, and sync Leaderboard rankings, Exam MCQs,
                30-Day Chapters, and Teacher Payouts in real time.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {needsAuth ? (
              <GoogleSignInButton
                onClick={handleGoogleLogin}
                disabled={isLoggingIn}
                label={
                  isLoggingIn ? 'Connecting to Google...' : 'Sign in with Google'
                }
              />
            ) : (
              <div className="flex flex-wrap items-center gap-2.5">
                <div className="inline-flex items-center gap-2 rounded-full border border-secondary/30 bg-secondary/10 px-4 py-2 text-xs font-semibold text-secondary">
                  <CheckCircle2 className="h-4 w-4" />
                  <span>
                    Connected:{' '}
                    {googleUser?.email ||
                      googleUser?.displayName ||
                      'Google Account'}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={handleGoogleDisconnect}
                  className="inline-flex h-10 items-center gap-1.5 rounded-full border border-border bg-background px-4 text-xs font-semibold hover:bg-accent"
                >
                  <LogOut className="h-3.5 w-3.5" /> Disconnect
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {needsAuth ? (
        <div className="rounded-3xl border border-dashed border-primary/40 bg-card p-10 text-center shadow-card">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-primary/10 text-primary">
            <FileSpreadsheet className="h-8 w-8" />
          </div>
          <h3 className="mt-4 text-xl font-bold">
            Sign in with Google to Access Your Spreadsheets
          </h3>
          <p className="mx-auto mt-2 max-w-lg text-sm text-muted-foreground">
            Authenticate with your Google account to read, create, and update
            Google Sheets for Uyanix 30 Days Challenge student leaderboards,
            exam question banks, and daily chapters.
          </p>
          <div className="mt-6 flex justify-center">
            <GoogleSignInButton
              onClick={handleGoogleLogin}
              disabled={isLoggingIn}
              label={
                isLoggingIn ? 'Signing in...' : 'Sign in with Google'
              }
            />
          </div>
        </div>
      ) : (
        <>
          {/* Create or Open Spreadsheet Bar */}
          <div className="grid gap-6 lg:grid-cols-12">
            {/* Left Column: Drive Spreadsheet Browser */}
            <div className="space-y-6 lg:col-span-5">
              {/* 1-Click Create Master Sheet */}
              <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
                <div className="flex items-center gap-2 text-base font-bold">
                  <Plus className="h-4 w-4 text-primary" /> Create New Uyanix
                  Spreadsheet
                </div>
                <p className="mt-1 text-xs text-muted-foreground">
                  Creates a structured Google Sheet in your Drive with{' '}
                  <b>Leaderboard</b>, <b>ExamQuestions</b>, <b>Chapters</b>, and{' '}
                  <b>Teachers</b> tabs.
                </p>

                <div className="mt-4 space-y-3">
                  <input
                    value={newSheetTitle}
                    onChange={(e) => setNewSheetTitle(e.target.value)}
                    placeholder="Spreadsheet Title..."
                    className="h-10 w-full rounded-xl border border-input bg-background px-3 text-sm outline-none focus:border-primary"
                  />
                  <button
                    type="button"
                    disabled={creatingSheet}
                    onClick={handleCreateMasterSpreadsheet}
                    className="inline-flex h-10 w-full items-center justify-center gap-2 rounded-full bg-gradient-hero px-5 text-xs font-semibold text-primary-foreground shadow-soft transition hover:opacity-95 disabled:opacity-60"
                  >
                    <Plus className="h-4 w-4" />
                    {creatingSheet
                      ? 'Creating in Google Drive...'
                      : 'Create Master Sheet in Drive'}
                  </button>
                </div>
              </div>

              {/* Open by URL / ID */}
              <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
                <div className="flex items-center gap-2 text-base font-bold">
                  <Table className="h-4 w-4 text-primary" /> Open by Google
                  Sheet URL or ID
                </div>
                <div className="mt-3 flex gap-2">
                  <input
                    value={spreadsheetInput}
                    onChange={(e) => setSpreadsheetInput(e.target.value)}
                    placeholder="Paste Google Sheet URL or Spreadsheet ID..."
                    className="h-10 flex-1 rounded-xl border border-input bg-background px-3 text-xs outline-none focus:border-primary"
                  />
                  <button
                    type="button"
                    onClick={() => loadSpreadsheetMetadata(spreadsheetInput)}
                    className="inline-flex h-10 items-center gap-1.5 rounded-full bg-primary px-4 text-xs font-semibold text-primary-foreground"
                  >
                    Open
                  </button>
                </div>
              </div>

              {/* Drive Spreadsheets List */}
              <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-base font-bold">
                    <FolderSearch className="h-4 w-4 text-primary" /> Your Drive
                    Spreadsheets
                  </div>
                  <button
                    type="button"
                    onClick={() => fetchDriveSpreadsheets(driveSearch)}
                    disabled={loadingDrive}
                    className="inline-flex h-8 items-center gap-1 rounded-full border border-border px-3 text-xs font-semibold hover:bg-accent"
                  >
                    <RefreshCw
                      className={`h-3.5 w-3.5 ${
                        loadingDrive ? 'animate-spin' : ''
                      }`}
                    />
                    Refresh
                  </button>
                </div>

                <div className="mt-3 flex gap-2">
                  <input
                    value={driveSearch}
                    onChange={(e) => setDriveSearch(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        fetchDriveSpreadsheets(driveSearch);
                      }
                    }}
                    placeholder="Search spreadsheets in Drive..."
                    className="h-9 flex-1 rounded-xl border border-input bg-background px-3 text-xs outline-none focus:border-primary"
                  />
                  <button
                    type="button"
                    onClick={() => fetchDriveSpreadsheets(driveSearch)}
                    className="h-9 rounded-xl border border-border bg-muted/60 px-3 text-xs font-semibold hover:bg-accent"
                  >
                    Search
                  </button>
                </div>

                <div className="mt-4 max-h-80 space-y-2 overflow-y-auto pr-1">
                  {loadingDrive ? (
                    <p className="py-6 text-center text-xs text-muted-foreground">
                      Loading your Google Drive spreadsheets...
                    </p>
                  ) : driveFiles.length === 0 ? (
                    <p className="py-6 text-center text-xs text-muted-foreground">
                      No spreadsheets found. Click &quot;Create Master Sheet in
                      Drive&quot; above to create one!
                    </p>
                  ) : (
                    driveFiles.map((file) => {
                      const isSelected = activeSpreadsheetId === file.id;
                      return (
                        <div
                          key={file.id}
                          className={`flex items-center justify-between gap-2 rounded-2xl border p-3 text-xs transition ${
                            isSelected
                              ? 'border-primary bg-accent/60'
                              : 'border-border bg-background hover:bg-muted/40'
                          }`}
                        >
                          <button
                            type="button"
                            onClick={() => loadSpreadsheetMetadata(file.id)}
                            className="flex-1 text-left"
                          >
                            <div className="font-semibold text-foreground line-clamp-1">
                              {file.name}
                            </div>
                            <div className="mt-0.5 text-[11px] text-muted-foreground">
                              Modified:{' '}
                              {file.modifiedTime
                                ? new Date(
                                    file.modifiedTime
                                  ).toLocaleDateString()
                                : 'Recently'}
                            </div>
                          </button>

                          <div className="flex items-center gap-1">
                            {file.webViewLink && (
                              <a
                                href={file.webViewLink}
                                target="_blank"
                                rel="noopener noreferrer"
                                title="Open in Google Sheets"
                                className="rounded-lg p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground"
                              >
                                <ExternalLink className="h-3.5 w-3.5" />
                              </a>
                            )}
                            <button
                              type="button"
                              onClick={() => handleDeleteDriveFile(file)}
                              title="Delete spreadsheet from Drive"
                              className="rounded-lg p-1.5 text-destructive hover:bg-destructive/10"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>

            {/* Right Column: Active Spreadsheet Workspace & Two-Way Sync */}
            <div className="space-y-6 lg:col-span-7">
              {!activeSpreadsheetId ? (
                <div className="flex h-full min-h-80 flex-col items-center justify-center rounded-3xl border border-border bg-card p-8 text-center shadow-card">
                  <Layers className="h-10 w-10 text-primary/60" />
                  <h3 className="mt-3 text-lg font-bold">
                    No Spreadsheet Selected
                  </h3>
                  <p className="mt-1 max-w-md text-xs text-muted-foreground">
                    Select any spreadsheet from your Google Drive list on the
                    left, paste a Spreadsheet URL/ID, or click{' '}
                    <b>Create Master Sheet in Drive</b> to start syncing Uyanix
                    data.
                  </p>
                </div>
              ) : (
                <div className="space-y-6">
                  {/* Spreadsheet Header & Dynamic Tab Selector */}
                  <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <div className="text-xs font-bold uppercase tracking-wider text-primary">
                          Active Google Spreadsheet
                        </div>
                        <h3 className="mt-0.5 text-xl font-extrabold">
                          {activeSpreadsheetTitle}
                        </h3>
                        <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                          ID: {activeSpreadsheetId}
                        </p>
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        {activeSpreadsheetUrl && (
                          <a
                            href={activeSpreadsheetUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex h-9 items-center gap-1.5 rounded-full border border-border bg-background px-3.5 text-xs font-semibold hover:bg-accent"
                          >
                            Open in Google Sheets{' '}
                            <ExternalLink className="h-3.5 w-3.5" />
                          </a>
                        )}
                        <button
                          type="button"
                          onClick={() =>
                            selectedTab &&
                            fetchTabValues(activeSpreadsheetId, selectedTab)
                          }
                          className="inline-flex h-9 items-center gap-1.5 rounded-full border border-border bg-background px-3.5 text-xs font-semibold hover:bg-accent"
                        >
                          <RefreshCw
                            className={`h-3.5 w-3.5 ${
                              loadingSheet ? 'animate-spin' : ''
                            }`}
                          />
                          Reload Tab
                        </button>
                      </div>
                    </div>

                    {/* Dynamic Sheet Tabs Selector (Fetched from Metadata) */}
                    <div className="mt-4">
                      <span className="text-xs font-semibold text-muted-foreground">
                        Select Sheet Tab (discovered from spreadsheet metadata):
                      </span>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {sheetTabs.map((tab) => (
                          <button
                            key={tab.sheetId}
                            type="button"
                            onClick={() => {
                              setSelectedTab(tab.title);
                              fetchTabValues(activeSpreadsheetId, tab.title);
                            }}
                            className={`rounded-full px-4 py-1.5 text-xs font-semibold transition ${
                              selectedTab === tab.title
                                ? 'bg-primary text-primary-foreground shadow-sm'
                                : 'border border-border bg-background hover:bg-accent'
                            }`}
                          >
                            {tab.title}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Two-Way Sync Actions Panel */}
                    <div className="mt-6 rounded-2xl border border-border bg-muted/30 p-4">
                      <div className="text-xs font-bold uppercase tracking-wider text-foreground">
                        Two-Way Uyanix Sync Actions (Target Tab:{' '}
                        <span className="text-primary">{selectedTab}</span>)
                      </div>

                      <div className="mt-3 grid gap-2 sm:grid-cols-2">
                        <button
                          type="button"
                          onClick={handleExportLeaderboardToSheet}
                          className="inline-flex h-10 items-center justify-center gap-2 rounded-xl bg-primary px-3 text-xs font-semibold text-primary-foreground transition hover:opacity-95"
                        >
                          <Upload className="h-3.5 w-3.5" /> Export Leaderboard
                          ({leaderboard.length}) → Sheet
                        </button>

                        <button
                          type="button"
                          onClick={handleImportLeaderboardFromSheet}
                          className="inline-flex h-10 items-center justify-center gap-2 rounded-xl border border-border bg-card px-3 text-xs font-semibold hover:bg-accent"
                        >
                          <Download className="h-3.5 w-3.5 text-primary" />{' '}
                          Import Leaderboard ← Sheet
                        </button>

                        <button
                          type="button"
                          onClick={handleExportQuestionsToSheet}
                          className="inline-flex h-10 items-center justify-center gap-2 rounded-xl bg-secondary px-3 text-xs font-semibold text-secondary-foreground transition hover:opacity-95"
                        >
                          <Upload className="h-3.5 w-3.5" /> Export Exam MCQs (
                          {customExamQuestions.length}) → Sheet
                        </button>

                        <button
                          type="button"
                          onClick={handleImportQuestionsFromSheet}
                          className="inline-flex h-10 items-center justify-center gap-2 rounded-xl border border-border bg-card px-3 text-xs font-semibold hover:bg-accent"
                        >
                          <Download className="h-3.5 w-3.5 text-secondary" />{' '}
                          Import Exam MCQs ← Sheet
                        </button>

                        <button
                          type="button"
                          onClick={handleExportChaptersToSheet}
                          className="inline-flex h-10 items-center justify-center gap-2 rounded-xl border border-border bg-card px-3 text-xs font-semibold hover:bg-accent"
                        >
                          <Upload className="h-3.5 w-3.5 text-primary" /> Export
                          30-Day Chapters → Sheet
                        </button>

                        <button
                          type="button"
                          onClick={handleImportChaptersFromSheet}
                          className="inline-flex h-10 items-center justify-center gap-2 rounded-xl border border-border bg-card px-3 text-xs font-semibold hover:bg-accent"
                        >
                          <Download className="h-3.5 w-3.5 text-primary" />{' '}
                          Import Chapters ← Sheet
                        </button>

                        <button
                          type="button"
                          onClick={handleExportTeachersToSheet}
                          className="inline-flex h-10 items-center justify-center gap-2 rounded-xl border border-border bg-card px-3 text-xs font-semibold hover:bg-accent sm:col-span-2"
                        >
                          <Upload className="h-3.5 w-3.5 text-saffron" /> Export
                          Teacher Referrals &amp; Payouts Ledger → Sheet
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Live Interactive Spreadsheet Table */}
                  <div className="rounded-3xl border border-border bg-card p-6 shadow-card">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <h4 className="text-base font-bold">
                          Tab Data: {selectedTab} ({gridRows.length} rows)
                        </h4>
                        <p className="text-xs text-muted-foreground">
                          Click any cell to edit values directly, then click
                          Save Changes to update Google Sheets.
                        </p>
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          type="button"
                          onClick={handleSaveEditedGrid}
                          disabled={gridRows.length === 0}
                          className="inline-flex h-9 items-center gap-1.5 rounded-full bg-primary px-4 text-xs font-semibold text-primary-foreground disabled:opacity-50"
                        >
                          <Save className="h-3.5 w-3.5" /> Save Changes
                        </button>
                        <button
                          type="button"
                          onClick={handleClearActiveTab}
                          disabled={gridRows.length === 0}
                          className="inline-flex h-9 items-center gap-1.5 rounded-full border border-destructive px-3.5 text-xs font-semibold text-destructive hover:bg-destructive/10 disabled:opacity-50"
                        >
                          <Eraser className="h-3.5 w-3.5" /> Clear Tab
                        </button>
                      </div>
                    </div>

                    <div className="mt-4 max-h-96 overflow-auto rounded-2xl border border-border">
                      {loadingSheet ? (
                        <div className="p-8 text-center text-xs text-muted-foreground">
                          Loading cells from &quot;{selectedTab}&quot;...
                        </div>
                      ) : gridRows.length === 0 ? (
                        <div className="p-8 text-center text-xs text-muted-foreground">
                          This tab is currently empty. Use one of the{' '}
                          <b>Export → Sheet</b> buttons above or append a row
                          below!
                        </div>
                      ) : (
                        <table className="w-full border-collapse text-xs">
                          <thead className="sticky top-0 bg-accent/80 backdrop-blur">
                            <tr>
                              <th className="border-b border-r border-border px-2.5 py-2 text-left font-mono text-[10px] text-muted-foreground">
                                #
                              </th>
                              {gridRows[0].map((headerCell, colIdx) => (
                                <th
                                  key={colIdx}
                                  className="border-b border-r border-border px-3 py-2 text-left font-bold text-foreground"
                                >
                                  {headerCell || `Col ${colIdx + 1}`}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {gridRows.map((row, rowIdx) => (
                              <tr
                                key={rowIdx}
                                className="border-b border-border hover:bg-muted/30"
                              >
                                <td className="border-r border-border bg-muted/20 px-2.5 py-1.5 font-mono text-[10px] text-muted-foreground">
                                  {rowIdx + 1}
                                </td>
                                {Array.from(
                                  {
                                    length: Math.max(
                                      gridRows[0]?.length || 1,
                                      row.length
                                    ),
                                  },
                                  (_, colIdx) => (
                                    <td
                                      key={colIdx}
                                      className="border-r border-border p-0"
                                    >
                                      <input
                                        value={row[colIdx] ?? ''}
                                        onChange={(e) => {
                                          const val = e.target.value;
                                          setGridRows((prev) =>
                                            prev.map((r, rIdx) => {
                                              if (rIdx !== rowIdx) return r;
                                              const copy = [...r];
                                              copy[colIdx] = val;
                                              return copy;
                                            })
                                          );
                                        }}
                                        className={`h-8 w-full min-w-28 bg-transparent px-2.5 text-xs outline-none focus:bg-accent/40 ${
                                          rowIdx === 0 ? 'font-bold' : ''
                                        }`}
                                      />
                                    </td>
                                  )
                                )}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </div>

                    {/* Quick Append Row Form */}
                    <form
                      onSubmit={handleAppendRow}
                      className="mt-4 rounded-2xl border border-border bg-muted/20 p-4"
                    >
                      <div className="text-xs font-semibold text-muted-foreground">
                        Append New Row to &quot;{selectedTab}&quot;
                      </div>
                      <div className="mt-2 grid gap-2 sm:grid-cols-5">
                        {newRowCells.slice(0, 5).map((cellVal, idx) => (
                          <input
                            key={idx}
                            value={cellVal}
                            onChange={(e) => {
                              const next = [...newRowCells];
                              next[idx] = e.target.value;
                              setNewRowCells(next);
                            }}
                            placeholder={
                              gridRows[0]?.[idx] || `Col ${idx + 1}`
                            }
                            className="h-9 rounded-xl border border-input bg-background px-2.5 text-xs outline-none focus:border-primary"
                          />
                        ))}
                      </div>
                      <button
                        type="submit"
                        className="mt-3 inline-flex h-9 items-center gap-1.5 rounded-full bg-secondary px-4 text-xs font-semibold text-secondary-foreground"
                      >
                        <Plus className="h-3.5 w-3.5" /> Append Row to Sheet
                      </button>
                    </form>
                  </div>
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {/* MANDATORY Explicit User Confirmation Modal for Destructive / Mutating Operations */}
      {pendingConfirmation && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-3xl border border-border bg-card p-6 shadow-soft">
            <div className="flex items-start gap-3">
              <div
                className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl ${
                  pendingConfirmation.variant === 'destructive'
                    ? 'bg-destructive/15 text-destructive'
                    : 'bg-primary/15 text-primary'
                }`}
              >
                <AlertTriangle className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-lg font-bold">
                  {pendingConfirmation.title}
                </h3>
                <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                  {pendingConfirmation.description}
                </p>
                <div className="mt-3 rounded-xl border border-border bg-muted/40 px-3 py-2 text-xs font-semibold text-foreground">
                  Affected Items: {pendingConfirmation.affectedCountLabel}
                </div>
              </div>
            </div>

            <div className="mt-6 flex items-center justify-end gap-2.5">
              <button
                type="button"
                disabled={executingConfirm}
                onClick={() => setPendingConfirmation(null)}
                className="h-10 rounded-full border border-border px-4 text-xs font-semibold hover:bg-accent disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={executingConfirm}
                onClick={executeConfirmedAction}
                className={`h-10 rounded-full px-5 text-xs font-semibold text-white shadow-soft transition hover:opacity-95 disabled:opacity-50 ${
                  pendingConfirmation.variant === 'destructive'
                    ? 'bg-destructive'
                    : 'bg-gradient-hero'
                }`}
              >
                {executingConfirm
                  ? 'Processing...'
                  : pendingConfirmation.confirmLabel}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
